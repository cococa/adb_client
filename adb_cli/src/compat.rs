//! Bundled adb_client entry point for the command-line interface used by scrcpy.
use std::{path::{Path, PathBuf}, process::ExitCode};
use adb_client::usb::find_all_connected_adb_devices;
use crate::direct_daemon::{self, Context};

fn walkdir(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() { files.extend(walkdir(&path)?); }
        else if path.is_file() { files.push(path); }
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
        println!("Android Debug Bridge compatibility (adb_client {})", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let key = std::env::var_os("MACANDROIDBRIDGE_ADB_KEY").map(PathBuf::from)
        .ok_or("MACANDROIDBRIDGE_ADB_KEY is not set")?;
    let mut serial = None;
    let mut endpoint = None;
    if args.first().map(String::as_str) == Some("-s") && args.len() >= 2 {
        serial = Some(args[1].clone());
        args.drain(0..2);
    }
    if args.first().map(String::as_str) == Some("usb") {
        args.remove(0);
        let mut vendor = None;
        let mut product = None;
        while args.first().is_some_and(|arg| arg.starts_with("--")) && args.len() >= 2 {
            match args[0].as_str() {
                "--vendor-id" => vendor = Some(u16::from_str_radix(&args[1], 16)?),
                "--product-id" => product = Some(u16::from_str_radix(&args[1], 16)?),
                "--private-key" => {}, // App supplies the same key in the environment.
                _ => return Err("unsupported USB option".into()),
            }
            args.drain(0..2);
        }
        endpoint = Some((vendor.ok_or("missing vendor")?, product.ok_or("missing product")?));
    }
    let devices = find_all_connected_adb_devices()?;
    if args.first().map(String::as_str) == Some("start-server") {
        // No device is needed to initialize the compatibility command layer.
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("wait-for-device") {
        if args.len() != 1 { return Err("wait-for-device does not accept arguments".into()); }
        loop {
            if !find_all_connected_adb_devices()?.is_empty() { break; }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("track-devices") {
        if args.len() != 1 { return Err("track-devices does not accept arguments".into()); }
        use std::io::Write;
        let mut previous = std::collections::BTreeMap::<String, String>::new();
        loop {
            let current_devices = find_all_connected_adb_devices()?;
            let mut current = std::collections::BTreeMap::<String, String>::new();
            for device in current_devices {
                let context = Context { key: key.clone(), vendor: device.vendor_id, product: device.product_id };
                let details = match direct_daemon::request(&context, "DEVICE_INFO") {
                    Ok(details) => details,
                    Err(error) => { eprintln!("adb_client: device temporarily unavailable: {error}"); continue; }
                };
                let serial = details.lines().next().unwrap_or("unknown").to_owned();
                current.insert(serial, "device".to_owned());
            }
            if current != previous {
                for (serial, state) in &current { if previous.get(serial) != Some(state) { println!("{serial}\t{state}"); } }
                for serial in previous.keys() { if !current.contains_key(serial) { println!("{serial}\toffline"); } }
                std::io::stdout().flush()?;
                previous = current;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    if args.first().map(String::as_str) == Some("devices") {
        println!("List of devices attached");
        for device in devices {
            let context = Context { key: key.clone(), vendor: device.vendor_id, product: device.product_id };
            let details = direct_daemon::request(&context, "DEVICE_INFO")?;
            let mut values = details.lines();
            let identifier = values.next().ok_or("missing serial")?;
            let model = values.next().unwrap_or("").replace(' ', "_");
            let product = values.next().unwrap_or("");
            println!("{identifier}\tdevice product:{product} model:{model}");
        }
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("features") {
        // The direct client currently exposes shell v2 and basic sync. It does
        // not implement compressed sync framing, so never advertise zstd.
        println!("shell_v2,cmd,sendrecv_v2");
        return Ok(());
    }
    let matches: Vec<_> = devices.iter().filter(|device| {
        endpoint.is_none_or(|(v, p)| device.vendor_id == v && device.product_id == p)
            && serial.as_ref().is_none_or(|serial| device.serial.as_ref() == Some(serial))
    }).collect();
    // Fail explicitly instead of silently addressing another phone.
    let device = match matches.as_slice() {
        [device] => *device,
        [] => return Err("selected Android USB device is not connected".into()),
        _ => return Err("multiple matching Android USB devices; select a unique device".into()),
    };
    if devices.iter().filter(|other| other.vendor_id == device.vendor_id && other.product_id == device.product_id).count() != 1 {
        return Err("two devices share the same USB vendor/product; connect one at a time".into());
    }
    let context = Context { key, vendor: device.vendor_id, product: device.product_id };
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
        Some("logcat") => {
            let command = if args.len() == 1 { "logcat".to_owned() } else {
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
            if transfer.len() < 2 { return Err("pull requires at least one source and a destination".into()); }
            let destination = PathBuf::from(transfer.pop().unwrap());
            let multi = transfer.len() > 1 || destination.is_dir();
            if multi { std::fs::create_dir_all(&destination)?; }
            for source in transfer {
                let mut listing = Vec::new();
                direct_daemon::stream_request_to(&context, &format!("SHELL\tfind '{}' -type f -print", source.replace('\'', "'\\''")), &mut listing)?;
                let files = String::from_utf8_lossy(&listing).lines().map(str::to_owned).collect::<Vec<_>>();
                let files = if files.is_empty() { vec![source.clone()] } else { files };
                let file_count = files.len();
                let base = Path::new(&source).file_name().ok_or("invalid remote path")?;
                for remote in files {
                    let relative = Path::new(&remote).strip_prefix(Path::new(&source)).unwrap_or(Path::new(Path::new(&remote).file_name().ok_or("invalid remote path")?));
                    let target = if file_count == 1 && !Path::new(&source).to_string_lossy().ends_with('/') && !multi { destination.clone() } else { destination.join(base).join(relative) };
                    if let Some(parent) = target.parent() { std::fs::create_dir_all(parent)?; }
                    let suffix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
                    let temporary = target.with_extension(format!("mab-{suffix}.partial"));
                    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                        let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
                        direct_daemon::stream_request_to(&context, &format!("PULL\t{remote}"), &mut output)?;
                        output.sync_all()?; drop(output); std::fs::rename(&temporary, &target)?; Ok(())
                    })();
                    if result.is_err() { let _ = std::fs::remove_file(&temporary); }
                    result?;
                }
            }
        }
        Some("install") => {
            let mut flags = Vec::new();
            let mut user = String::new();
            let mut source = None;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "-r" | "-g" | "-d" => flags.push(args[index].clone()),
                    "--user" | "-u" => {
                        index += 1;
                        user = args.get(index).ok_or("missing install user")?.clone();
                    }
                    value if value.starts_with('-') => return Err("unsupported install option".into()),
                    value => source = Some(value.to_owned()),
                }
                index += 1;
            }
            let source = source.ok_or("missing APK path")?;
            if source.contains(['\n', '\r', '\t']) || (!user.is_empty() && !user.bytes().all(|b| b.is_ascii_digit())) {
                return Err("invalid install request".into());
            }
            print!("{}", direct_daemon::request(&context, &format!("INSTALL\t{source}\t{}\t{user}", flags.join(" ")))?);
        }
        Some("uninstall") => {
            let mut flags = String::new();
            let mut user = String::new();
            let mut package = None;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "-k" => flags = "-k".to_owned(),
                    "--user" | "-u" => {
                        index += 1;
                        user = args.get(index).ok_or("missing uninstall user")?.clone();
                    }
                    value if value.starts_with('-') => return Err("unsupported uninstall option".into()),
                    value => package = Some(value.to_owned()),
                }
                index += 1;
            }
            let package = package.ok_or("missing package name")?;
            if !package.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_') {
                return Err("invalid package name".into());
            }
            print!("{}", direct_daemon::request(&context, &format!("UNINSTALL\t{flags}\t{user}\t{package}"))?);
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
            if transfer.len() < 2 { return Err("push requires at least one source and a destination".into()); }
            let destination = transfer.pop().unwrap();
            if destination.contains(['\n', '\r', '\t']) { return Err("invalid push destination".into()); }
            for path in &transfer { if path.contains(['\n', '\r', '\t']) { return Err("invalid push path".into()); } }
            let multi = transfer.len() > 1 || transfer.iter().any(|p| Path::new(p).is_dir());
            if multi { direct_daemon::request(&context, &format!("SHELL\tmkdir -p '{}'", destination.replace('\'', "'\\''")))?; }
            for source in transfer {
                let source_path = Path::new(&source);
                let base = source_path.file_name().ok_or("invalid local path")?.to_string_lossy();
                let mut files = Vec::new();
                if source_path.is_dir() {
                    for entry in walkdir(&source_path)? { files.push(entry); }
                } else { files.push(source_path.to_path_buf()); }
                for file in files {
                    let relative = file.strip_prefix(source_path).unwrap_or(Path::new(file.file_name().ok_or("invalid local path")?));
                    let remote = if multi { format!("{destination}/{base}/{}", relative.to_string_lossy()) } else { destination.clone() };
                    if let Some(parent) = Path::new(&remote).parent() { direct_daemon::request(&context, &format!("SHELL\tmkdir -p '{}'
", parent.to_string_lossy().replace('\'', "'\\''")))?; }
                    direct_daemon::request(&context, &format!("PUSH\t{}\t{}", file.to_string_lossy(), remote))?;
                }
            }
        }
        Some("reverse") if args.get(1).map(String::as_str) == Some("--remove") && args.len() == 3 => {
            direct_daemon::request(&context, &format!("REVERSE_REMOVE\t{}", args[2]))?;
        }
        Some("reverse") if args.get(1).map(String::as_str) == Some("--list") && args.len() == 2 => {
            print!("{}", direct_daemon::request(&context, "REVERSE_LIST")?);
        }
        Some("reverse") if args.get(1).map(String::as_str) == Some("--remove-all") && args.len() == 2 => {
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
        Some("forward") if args.get(1).map(String::as_str) == Some("--remove") && args.len() == 3 => {
            direct_daemon::request(&context, &format!("FORWARD_REMOVE\t{}", args[2]))?;
        }
        _ => return Err(format!("unsupported direct-USB command: {}", args.join(" ")).into()),
    }
    Ok(())
}
