//! Bundled adb_client entry point for the command-line interface used by scrcpy.
use crate::direct_daemon::{self, Context};
use adb_client::{
    ADBDeviceExt, mdns::MDNSDiscoveryService, tcp::ADBTcpDevice,
    usb::find_all_connected_adb_devices, wireless,
};
use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

fn wireless_endpoints_path(key: &Path) -> PathBuf {
    key.with_file_name("wireless-endpoints")
}

fn wireless_endpoints(key: &Path) -> Result<BTreeSet<SocketAddr>, Box<dyn std::error::Error>> {
    let path = wireless_endpoints_path(key);
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error.into()),
    };
    content
        .lines()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

fn save_wireless_endpoints(
    key: &Path,
    endpoints: &BTreeSet<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wireless_endpoints_path(key);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    use std::io::Write;
    let mut file = options.open(path)?;
    for endpoint in endpoints {
        writeln!(file, "{endpoint}")?;
    }
    file.sync_all()?;
    Ok(())
}

fn connect_wireless(address: SocketAddr, key: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut device = ADBTcpDevice::new_with_custom_private_key(address, key)?;
    let mut serial = Vec::new();
    device.shell_command(&"getprop ro.serialno", Some(&mut serial), None)?;
    let serial = String::from_utf8(serial)?.trim().to_owned();
    Ok(if serial.is_empty() {
        address.to_string()
    } else {
        serial
    })
}

struct InstallRequest {
    flags: Vec<String>,
    user: Option<String>,
    source: String,
}

/// Parses precisely the install subset used by MacAndRoidBridge. Keeping this
/// shared between USB and wireless transports prevents one connection type
/// from silently accepting a different APK-install request.
fn parse_install_request(args: &[String]) -> Result<InstallRequest, Box<dyn std::error::Error>> {
    let mut flags = Vec::new();
    let mut user = None;
    let mut source = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-r" | "-g" | "-d" => flags.push(args[index].clone()),
            "--user" | "-u" => {
                index += 1;
                user = Some(args.get(index).ok_or("missing install user")?.clone());
            }
            value if value.starts_with('-') => return Err("unsupported install option".into()),
            value => {
                if source.replace(value.to_owned()).is_some() {
                    return Err("install accepts exactly one APK path".into());
                }
            }
        }
        index += 1;
    }
    let source = source.ok_or("missing APK path")?;
    if source.contains(['\n', '\r', '\t'])
        || user
            .as_ref()
            .is_some_and(|value| !value.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("invalid install request".into());
    }
    Ok(InstallRequest {
        flags,
        user,
        source,
    })
}

struct UninstallRequest {
    keep_data: bool,
    user: Option<String>,
    package: String,
}

fn parse_uninstall_request(
    args: &[String],
) -> Result<UninstallRequest, Box<dyn std::error::Error>> {
    let mut keep_data = false;
    let mut user = None;
    let mut package = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-k" => keep_data = true,
            "--user" | "-u" => {
                index += 1;
                user = Some(args.get(index).ok_or("missing uninstall user")?.clone());
            }
            value if value.starts_with('-') => return Err("unsupported uninstall option".into()),
            value => {
                if package.replace(value.to_owned()).is_some() {
                    return Err("uninstall accepts exactly one package name".into());
                }
            }
        }
        index += 1;
    }
    let package = package.ok_or("missing package name")?;
    if !package
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        || user
            .as_ref()
            .is_some_and(|value| !value.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("invalid uninstall request".into());
    }
    Ok(UninstallRequest {
        keep_data,
        user,
        package,
    })
}

fn install_wireless(
    device: &mut ADBTcpDevice,
    request: InstallRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let remote = format!(
        "/data/local/tmp/mab-install-{}-{suffix}.apk",
        std::process::id()
    );
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut input = fs::File::open(&request.source)?;
        device.push(&mut input, &remote)?;
        let user_flag = request
            .user
            .map_or_else(String::new, |user| format!(" --user {user}"));
        let mut output = Vec::new();
        device.shell_command(
            &format!("pm install {}{user_flag} {remote}", request.flags.join(" ")),
            Some(&mut output),
            None,
        )?;
        if String::from_utf8_lossy(&output)
            .lines()
            .any(|line| line.trim() == "Success")
        {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output).trim().to_owned().into())
        }
    })();
    let _ = device.shell_command(&format!("rm -f {remote}"), None, None);
    result
}

fn uninstall_wireless(
    device: &mut ADBTcpDevice,
    request: UninstallRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let keep_flag = if request.keep_data { "-k " } else { "" };
    let user_flag = request
        .user
        .map_or_else(String::new, |user| format!("--user {user} "));
    let mut output = Vec::new();
    device.shell_command(
        &format!("pm uninstall {keep_flag}{user_flag}{}", request.package),
        Some(&mut output),
        None,
    )?;
    if String::from_utf8_lossy(&output)
        .lines()
        .any(|line| line.trim() == "Success")
    {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output).trim().to_owned().into())
    }
}

fn push_wireless(
    device: &mut ADBTcpDevice,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transfer = args[1..].to_vec();
    transfer.retain(|arg| arg != "-z" && arg != "-Z" && arg != "zstd");
    if transfer.len() < 2 {
        return Err("push requires at least one source and a destination".into());
    }
    let destination = transfer.pop().unwrap();
    if destination.contains(['\n', '\r', '\t'])
        || transfer
            .iter()
            .any(|path| path.contains(['\n', '\r', '\t']))
    {
        return Err("invalid push request".into());
    }
    let multi = transfer.len() > 1 || transfer.iter().any(|path| Path::new(path).is_dir());
    if multi {
        device.shell_command(
            &format!("mkdir -p '{}'", destination.replace('\'', "'\\''")),
            None,
            None,
        )?;
    }
    for source in transfer {
        let source_path = Path::new(&source);
        let base = source_path
            .file_name()
            .ok_or("invalid local path")?
            .to_string_lossy();
        let files = if source_path.is_dir() {
            walkdir(source_path)?
        } else {
            vec![source_path.to_path_buf()]
        };
        for file in files {
            let relative = file
                .strip_prefix(source_path)
                .unwrap_or(Path::new(file.file_name().ok_or("invalid local path")?));
            let remote = if multi {
                format!("{destination}/{base}/{}", relative.to_string_lossy())
            } else {
                destination.clone()
            };
            if let Some(parent) = Path::new(&remote).parent() {
                device.shell_command(
                    &format!(
                        "mkdir -p '{}'",
                        parent.to_string_lossy().replace('\'', "'\\''")
                    ),
                    None,
                    None,
                )?;
            }
            let mut input = fs::File::open(&file)?;
            device.push(&mut input, &remote)?;
        }
    }
    Ok(())
}

/// Executes commands that do not need a process-persistent reverse or forward
/// relay over one authenticated Android wireless-debugging connection.
fn run_wireless_device_command(
    address: SocketAddr,
    key: &Path,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut device = ADBTcpDevice::new_with_custom_private_key(address, key)?;
    match args.first().map(String::as_str) {
        Some("features") if args.len() == 1 => {
            // Keep this identical to USB: Sync v2 is available, while zstd is
            // deliberately not advertised until compressed framing exists.
            println!("shell_v2,cmd,sendrecv_v2");
        }
        Some("get-state") if args.len() == 1 => println!("device"),
        Some("get-serialno") if args.len() == 1 => println!("{address}"),
        Some("get-devpath") if args.len() == 1 => println!("tcp:{address}"),
        Some("shell") | Some("exec-out") => {
            let command = args[1..].join(" ");
            if args[0] == "shell" {
                device.shell_command(
                    &command,
                    Some(&mut std::io::stdout()),
                    Some(&mut std::io::stderr()),
                )?;
            } else {
                device.exec(&command, &mut std::io::empty(), Box::new(std::io::stdout()))?;
            }
        }
        Some("pull-stream") if args.len() == 2 => {
            device.pull(&args[1], &mut std::io::stdout())?;
        }
        Some("pull") if args.len() == 3 => {
            let mut output = fs::File::create(&args[2])?;
            device.pull(&args[1], &mut output)?;
        }
        Some("push") => push_wireless(&mut device, args)?,
        Some("install") => install_wireless(&mut device, parse_install_request(args)?)?,
        Some("uninstall") => uninstall_wireless(&mut device, parse_uninstall_request(args)?)?,
        Some("root") if args.len() == 1 => device.root()?,
        Some("remount") if args.len() == 1 => {
            device.remount()?;
        }
        Some("reboot") if args.len() == 1 => device.reboot(adb_client::RebootType::System)?,
        Some("reverse")
            if args.get(1).map(String::as_str) == Some("--remove") && args.len() == 3 =>
        {
            device.remove_reverse_forward(args[2].clone())?;
        }
        Some("reverse") if args.len() == 3 => {
            // The relay must own its TCP ADB transport for as long as scrcpy
            // is connected. Run the existing native TCP relay as a managed
            // child instead of returning after installing a short-lived rule.
            Command::new(std::env::current_exe()?)
                .arg("tcp")
                .arg(address.to_string())
                .arg("--private-key")
                .arg(key)
                .arg("reverse-relay")
                .arg(&args[1])
                .arg(&args[2])
                .env_remove("MACANDROIDBRIDGE_ADB_KEY")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
        }
        Some("forward") => {
            return Err("wireless forward relay is not yet implemented".into());
        }
        _ => return Err(format!("unsupported wireless command: {}", args.join(" ")).into()),
    }
    Ok(())
}

fn walkdir(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            files.extend(walkdir(&path)?);
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(files)
}

pub fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("adb_client: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("version") {
        println!(
            "Android Debug Bridge compatibility (adb_client {})",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    let key = std::env::var_os("MACANDROIDBRIDGE_ADB_KEY")
        .map(PathBuf::from)
        .ok_or("MACANDROIDBRIDGE_ADB_KEY is not set")?;
    let mut serial = None;
    let mut endpoint = None;
    if args.first().map(String::as_str) == Some("-s") && args.len() >= 2 {
        serial = Some(args[1].clone());
        args.drain(0..2);
    }
    if args.first().map(String::as_str) == Some("usb") {
        args.remove(0);
        if args.as_slice() == ["--list"] {
            let devices = find_all_connected_adb_devices()?;
            println!("Index\tVendor ID\tProduct ID\tDevice Description");
            println!("-----\t---------\t----------\t----------------");
            for (index, device) in devices.iter().enumerate() {
                println!(
                    "#{index}\t{:04x}\t{:04x}\t{}",
                    device.vendor_id, device.product_id, device.device_description
                );
            }
            return Ok(());
        }
        let mut vendor = None;
        let mut product = None;
        while args.first().is_some_and(|arg| arg.starts_with("--")) && args.len() >= 2 {
            match args[0].as_str() {
                "--vendor-id" => vendor = Some(u16::from_str_radix(&args[1], 16)?),
                "--product-id" => product = Some(u16::from_str_radix(&args[1], 16)?),
                "--private-key" => {} // App supplies the same key in the environment.
                _ => return Err("unsupported USB option".into()),
            }
            args.drain(0..2);
        }
        endpoint = Some((
            vendor.ok_or("missing vendor")?,
            product.ok_or("missing product")?,
        ));
    }
    match args.first().map(String::as_str) {
        Some("pair") if args.len() == 3 => {
            let address: SocketAddr = args[1].parse()?;
            let guid = wireless::pair(address, &args[2], &key)?;
            println!("Successfully paired to {address} [{guid}]");
            return Ok(());
        }
        Some("connect") if args.len() == 2 => {
            let address: SocketAddr = args[1].parse()?;
            let serial = connect_wireless(address, &key)?;
            let mut endpoints = wireless_endpoints(&key)?;
            endpoints.insert(address);
            save_wireless_endpoints(&key, &endpoints)?;
            println!("connected to {address} ({serial})");
            return Ok(());
        }
        Some("disconnect") if args.len() <= 2 => {
            let mut endpoints = wireless_endpoints(&key)?;
            if let Some(value) = args.get(1) {
                if value != "-a" {
                    endpoints.remove(&value.parse()?);
                    println!("disconnected {value}");
                } else {
                    endpoints.clear();
                    println!("disconnected everything");
                }
            } else {
                endpoints.clear();
                println!("disconnected everything");
            }
            save_wireless_endpoints(&key, &endpoints)?;
            return Ok(());
        }
        Some("mdns") if args.get(1).map(String::as_str) == Some("check") && args.len() == 2 => {
            let mut service = MDNSDiscoveryService::new()?;
            service.shutdown()?;
            println!("mdns discovery is available");
            return Ok(());
        }
        Some("mdns") if args.get(1).map(String::as_str) == Some("services") && args.len() == 2 => {
            let mut service = MDNSDiscoveryService::new()?;
            let (sender, receiver) = std::sync::mpsc::channel();
            service.start(sender)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut discovered = BTreeSet::new();
            while std::time::Instant::now() < deadline {
                if let Ok(device) = receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                    for address in device.addresses() {
                        discovered.insert(format!(
                            "{}\\t{}:{}",
                            device.fullname,
                            address,
                            device.port()
                        ));
                    }
                }
            }
            service.shutdown()?;
            for device in discovered {
                println!("{device}");
            }
            return Ok(());
        }
        Some("pair") => return Err("usage: adb pair HOST:PORT PAIRING_CODE".into()),
        Some("connect") => return Err("usage: adb connect HOST:PORT".into()),
        Some("disconnect") => return Err("usage: adb disconnect [HOST:PORT|-a]".into()),
        Some("mdns") => return Err("usage: adb mdns check|services".into()),
        _ => {}
    }
    if endpoint.is_none()
        && let Some(address) = serial
            .as_deref()
            .and_then(|value| value.parse::<SocketAddr>().ok())
    {
        if !wireless_endpoints(&key)?.contains(&address) {
            return Err("selected wireless Android device is not connected; run adb connect HOST:PORT first".into());
        }
        return run_wireless_device_command(address, &key, &args);
    }
    let devices = find_all_connected_adb_devices()?;
    if args.first().map(String::as_str) == Some("start-server") {
        // No device is needed to initialize the compatibility command layer.
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("wait-for-device") {
        if args.len() != 1 {
            return Err("wait-for-device does not accept arguments".into());
        }
        loop {
            if !find_all_connected_adb_devices()?.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("track-devices") {
        if args.len() != 1 {
            return Err("track-devices does not accept arguments".into());
        }
        use std::io::Write;
        let mut previous = std::collections::BTreeMap::<String, String>::new();
        loop {
            let current_devices = find_all_connected_adb_devices()?;
            let mut current = std::collections::BTreeMap::<String, String>::new();
            for device in current_devices {
                let context = Context {
                    key: key.clone(),
                    vendor: device.vendor_id,
                    product: device.product_id,
                };
                let details = match direct_daemon::request(&context, "DEVICE_INFO") {
                    Ok(details) => details,
                    Err(error) => {
                        eprintln!("adb_client: device temporarily unavailable: {error}");
                        continue;
                    }
                };
                let serial = details.lines().next().unwrap_or("unknown").to_owned();
                current.insert(serial, "device".to_owned());
            }
            if current != previous {
                for (serial, state) in &current {
                    if previous.get(serial) != Some(state) {
                        println!("{serial}\t{state}");
                    }
                }
                for serial in previous.keys() {
                    if !current.contains_key(serial) {
                        println!("{serial}\toffline");
                    }
                }
                std::io::stdout().flush()?;
                previous = current;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    if args.first().map(String::as_str) == Some("devices") {
        if args.len() > 2 || args.get(1).is_some_and(|option| option != "-l") {
            return Err("usage: adb devices [-l]".into());
        }
        println!("List of devices attached");
        for device in devices {
            let context = Context {
                key: key.clone(),
                vendor: device.vendor_id,
                product: device.product_id,
            };
            let details = direct_daemon::request(&context, "DEVICE_INFO")?;
            let mut values = details.lines();
            let identifier = values.next().ok_or("missing serial")?;
            let model = values.next().unwrap_or("").replace(' ', "_");
            let product = values.next().unwrap_or("");
            println!("{identifier}\tdevice product:{product} model:{model}");
        }
        for address in wireless_endpoints(&key)? {
            match connect_wireless(address, &key) {
                Ok(serial) => println!("{address}\tdevice product:wireless model:{serial}"),
                Err(_) => println!("{address}\toffline transport_id:wireless"),
            }
        }
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("features") {
        // The direct client currently exposes shell v2 and basic sync. It does
        // not implement compressed sync framing, so never advertise zstd.
        println!("shell_v2,cmd,sendrecv_v2");
        return Ok(());
    }
    // `adb -s` takes the serial presented to callers, which is obtained from
    // DEVICE_INFO after authentication. IOKit's provisional serial is absent
    // on some USB devices, so resolve the public serial through the existing
    // dispatcher before choosing a transport.
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| {
            endpoint.is_none_or(|(v, p)| device.vendor_id == v && device.product_id == p)
        })
        .filter(|device| {
            let Some(requested_serial) = serial.as_ref() else {
                return true;
            };
            if device.serial.as_ref() == Some(requested_serial) {
                return true;
            }
            let context = Context {
                key: key.clone(),
                vendor: device.vendor_id,
                product: device.product_id,
            };
            direct_daemon::request(&context, "DEVICE_INFO")
                .ok()
                .and_then(|details| details.lines().next().map(str::to_owned))
                .as_ref()
                == Some(requested_serial)
        })
        .collect();
    // Fail explicitly instead of silently addressing another phone.
    let device = match matches.as_slice() {
        [device] => *device,
        [] => return Err("selected Android USB device is not connected".into()),
        _ => return Err("multiple matching Android USB devices; select a unique device".into()),
    };
    // P0 multi-device work: USB location/interface identity must replace this
    // vendor/product guard so two identical phones can keep independent
    // authenticated dispatchers. Do not weaken the guard before that mapping
    // exists, or a command may operate on the wrong device.
    if devices
        .iter()
        .filter(|other| {
            other.vendor_id == device.vendor_id && other.product_id == device.product_id
        })
        .count()
        != 1
    {
        return Err("two devices share the same USB vendor/product; connect one at a time".into());
    }
    let context = Context {
        key,
        vendor: device.vendor_id,
        product: device.product_id,
    };
    match args.first().map(String::as_str) {
        Some("get-state") => println!("device"),
        Some("get-serialno") => {
            let details = direct_daemon::request(&context, "DEVICE_INFO")?;
            println!("{}", details.lines().next().unwrap_or("unknown"));
        }
        Some("get-devpath") => println!("usb:{:04x}:{:04x}", device.vendor_id, device.product_id),
        Some("root") if args.len() == 1 => {
            direct_daemon::request(&context, "ROOT")?;
        }
        Some("remount") if args.len() == 1 => {
            direct_daemon::request(&context, "REMOUNT")?;
        }
        Some("tcpip") if args.len() == 2 => {
            let port = args[1].parse::<u16>()?;
            if port == 0 {
                return Err("tcpip port must be between 1 and 65535".into());
            }
            direct_daemon::request(&context, &format!("TCPIP\\t{port}"))?;
            println!("restarting in TCP mode port: {port}");
        }
        Some("logcat") => {
            let command = if args.len() == 1 {
                "logcat".to_owned()
            } else {
                format!("logcat {}", args[1..].join(" "))
            };
            direct_daemon::stream_request(&context, &format!("SHELL\t{command}"))?;
        }
        Some("stat") | Some("stat2") if args.len() == 2 => {
            let path = args[1].replace('\'', "'\\''");
            // Keep the output textual and stable for file-management callers:
            // name, byte size, octal mode, and modification time.
            direct_daemon::stream_request(
                &context,
                &format!("SHELL\tstat -c '%n %s %a %Y' -- '{path}'"),
            )?;
        }
        Some("shell") | Some("exec-out") => {
            let kind = if args[0] == "shell" { "SHELL" } else { "EXEC" };
            // Accept the common PTY switches. The direct transport always uses
            // a non-interactive raw stream, which is the safe mode for App use.
            let mut command_args = args[1..].to_vec();
            while let Some(option) = command_args.first().map(String::as_str) {
                if matches!(option, "-T" | "-t" | "-tt" | "-x" | "--") {
                    command_args.remove(0);
                } else if option == "-n" {
                    command_args.drain(0..1);
                } else {
                    break;
                }
            }
            let command = command_args.join(" ");
            direct_daemon::stream_request(&context, &format!("{kind}\t{command}"))?;
        }
        Some("pull-stream") if args.len() == 2 => {
            direct_daemon::stream_request(&context, &format!("PULL\t{}", args[1]))?;
        }
        Some("pull") => {
            let mut transfer = args[1..].to_vec();
            transfer.retain(|arg| arg != "-z" && arg != "-Z" && arg != "zstd");
            if transfer.len() < 2 {
                return Err("pull requires at least one source and a destination".into());
            }
            let destination = PathBuf::from(transfer.pop().unwrap());
            let multi = transfer.len() > 1 || destination.is_dir();
            if multi {
                std::fs::create_dir_all(&destination)?;
            }
            for source in transfer {
                let mut listing = Vec::new();
                direct_daemon::stream_request_to(
                    &context,
                    &format!(
                        "SHELL\tfind '{}' -type f -print",
                        source.replace('\'', "'\\''")
                    ),
                    &mut listing,
                )?;
                let files = String::from_utf8_lossy(&listing)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let files = if files.is_empty() {
                    vec![source.clone()]
                } else {
                    files
                };
                let file_count = files.len();
                let base = Path::new(&source)
                    .file_name()
                    .ok_or("invalid remote path")?;
                for remote in files {
                    let relative = Path::new(&remote)
                        .strip_prefix(Path::new(&source))
                        .unwrap_or(Path::new(
                            Path::new(&remote)
                                .file_name()
                                .ok_or("invalid remote path")?,
                        ));
                    let target = if file_count == 1
                        && !Path::new(&source).to_string_lossy().ends_with('/')
                        && !multi
                    {
                        destination.clone()
                    } else {
                        destination.join(base).join(relative)
                    };
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let suffix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_nanos();
                    let temporary = target.with_extension(format!("mab-{suffix}.partial"));
                    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                        let mut output = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&temporary)?;
                        direct_daemon::stream_request_to(
                            &context,
                            &format!("PULL\t{remote}"),
                            &mut output,
                        )?;
                        output.sync_all()?;
                        drop(output);
                        std::fs::rename(&temporary, &target)?;
                        Ok(())
                    })();
                    if result.is_err() {
                        let _ = std::fs::remove_file(&temporary);
                    }
                    result?;
                }
            }
        }
        Some("install") => {
            let request = parse_install_request(&args)?;
            print!(
                "{}",
                direct_daemon::request(
                    &context,
                    &format!(
                        "INSTALL\t{}\t{}\t{}",
                        request.source,
                        request.flags.join(" "),
                        request.user.unwrap_or_default()
                    )
                )?
            );
        }
        Some("uninstall") => {
            let request = parse_uninstall_request(&args)?;
            print!(
                "{}",
                direct_daemon::request(
                    &context,
                    &format!(
                        "UNINSTALL\t{}\t{}\t{}",
                        if request.keep_data { "-k" } else { "" },
                        request.user.unwrap_or_default(),
                        request.package
                    )
                )?
            );
        }
        Some("reboot") => {
            let mode = args.get(1).map(String::as_str).unwrap_or("");
            if args.len() > 2 || !matches!(mode, "" | "bootloader" | "recovery" | "sideload") {
                return Err("unsupported reboot mode".into());
            }
            direct_daemon::request(&context, &format!("SHELL\treboot {mode}"))?;
        }
        Some("push") => {
            let mut transfer = args[1..].to_vec();
            transfer.retain(|arg| arg != "-z" && arg != "-Z" && arg != "zstd");
            if transfer.len() < 2 {
                return Err("push requires at least one source and a destination".into());
            }
            let destination = transfer.pop().unwrap();
            if destination.contains(['\n', '\r', '\t']) {
                return Err("invalid push destination".into());
            }
            for path in &transfer {
                if path.contains(['\n', '\r', '\t']) {
                    return Err("invalid push path".into());
                }
            }
            let multi = transfer.len() > 1 || transfer.iter().any(|p| Path::new(p).is_dir());
            if multi {
                direct_daemon::request(
                    &context,
                    &format!("SHELL\tmkdir -p '{}'", destination.replace('\'', "'\\''")),
                )?;
            }
            for source in transfer {
                let source_path = Path::new(&source);
                let base = source_path
                    .file_name()
                    .ok_or("invalid local path")?
                    .to_string_lossy();
                let mut files = Vec::new();
                if source_path.is_dir() {
                    for entry in walkdir(&source_path)? {
                        files.push(entry);
                    }
                } else {
                    files.push(source_path.to_path_buf());
                }
                for file in files {
                    let relative = file
                        .strip_prefix(source_path)
                        .unwrap_or(Path::new(file.file_name().ok_or("invalid local path")?));
                    let remote = if multi {
                        format!("{destination}/{base}/{}", relative.to_string_lossy())
                    } else {
                        destination.clone()
                    };
                    if let Some(parent) = Path::new(&remote).parent() {
                        direct_daemon::request(
                            &context,
                            &format!(
                                "SHELL\tmkdir -p '{}'
",
                                parent.to_string_lossy().replace('\'', "'\\''")
                            ),
                        )?;
                    }
                    direct_daemon::request(
                        &context,
                        &format!("PUSH\t{}\t{}", file.to_string_lossy(), remote),
                    )?;
                }
            }
        }
        Some("reverse")
            if args.get(1).map(String::as_str) == Some("--remove") && args.len() == 3 =>
        {
            direct_daemon::request(&context, &format!("REVERSE_REMOVE\t{}", args[2]))?;
        }
        Some("reverse") if args.get(1).map(String::as_str) == Some("--list") && args.len() == 2 => {
            print!("{}", direct_daemon::request(&context, "REVERSE_LIST")?);
        }
        Some("reverse")
            if args.get(1).map(String::as_str) == Some("--remove-all") && args.len() == 2 =>
        {
            direct_daemon::request(&context, "REVERSE_REMOVE_ALL")?;
        }
        Some("reverse") if args.len() == 3 => {
            direct_daemon::request(&context, &format!("REVERSE\t{}\t{}", args[1], args[2]))?;
        }
        Some("forward") if args.len() == 3 => {
            direct_daemon::request(&context, &format!("FORWARD\t{}\t{}", args[1], args[2]))?;
        }
        Some("forward") if args.get(1).map(String::as_str) == Some("--list") && args.len() == 2 => {
            print!("{}", direct_daemon::request(&context, "FORWARD_LIST")?);
        }
        Some("forward")
            if args.get(1).map(String::as_str) == Some("--remove") && args.len() == 3 =>
        {
            direct_daemon::request(&context, &format!("FORWARD_REMOVE\t{}", args[2]))?;
        }
        _ => return Err(format!("unsupported direct-USB command: {}", args.join(" ")).into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_install_request, parse_uninstall_request};

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn install_request_keeps_app_flags_and_user() {
        let request = parse_install_request(&values(&[
            "install",
            "-r",
            "-g",
            "--user",
            "10",
            "/tmp/example.apk",
        ]))
        .unwrap();
        assert_eq!(request.flags, ["-r", "-g"]);
        assert_eq!(request.user.as_deref(), Some("10"));
        assert_eq!(request.source, "/tmp/example.apk");
    }

    #[test]
    fn uninstall_request_keeps_data_and_user() {
        let request = parse_uninstall_request(&values(&[
            "uninstall",
            "-k",
            "--user",
            "0",
            "com.example.app",
        ]))
        .unwrap();
        assert!(request.keep_data);
        assert_eq!(request.user.as_deref(), Some("0"));
        assert_eq!(request.package, "com.example.app");
    }

    #[test]
    fn package_requests_reject_unsupported_options() {
        assert!(parse_install_request(&values(&["install", "--instant", "a.apk"])).is_err());
        assert!(
            parse_uninstall_request(&values(&["uninstall", "--all", "com.example.app"])).is_err()
        );
    }
}
