//! Bundled adb_client entry point for the command-line interface used by scrcpy.
use crate::{
    direct_daemon::{self, Context},
    wireless_forward_daemon,
};
use adb_client::{
    ADBDeviceExt, RebootType,
    mdns::MDNSDiscoveryService,
    server::{ADBServer, DeviceLong},
    server_device::ADBServerDevice,
    tcp::ADBTcpDevice,
    usb::{ADBDeviceInfo, find_all_connected_adb_devices},
    wireless,
};
use std::{
    collections::BTreeSet,
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

fn stable_transport_id(kind: &str, identity: &str) -> u64 {
    kind.bytes()
        .chain([0])
        .chain(identity.bytes())
        .fold(0xcbf2_9ce4_8422_2325u64, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
        .max(1)
}

fn usb_transport_id(device: &ADBDeviceInfo) -> u64 {
    let identity = device.location_id.map_or_else(
        || {
            device
                .serial
                .clone()
                .unwrap_or_else(|| format!("{:04x}:{:04x}", device.vendor_id, device.product_id))
        },
        |location| format!("{location:016x}"),
    );
    stable_transport_id("usb", &identity)
}

fn usb_context(key: &Path, device: &ADBDeviceInfo) -> Context {
    Context {
        key: key.to_path_buf(),
        vendor: device.vendor_id,
        product: device.product_id,
        location: device.location_id.unwrap_or(0),
    }
}

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TransferOptions {
    archive: bool,
    dry_run: bool,
    quiet: bool,
    sync: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct TransferRequest {
    options: TransferOptions,
    paths: Vec<String>,
}

fn transfer_paths(
    args: &[String],
    operation: &str,
) -> Result<TransferRequest, Box<dyn std::error::Error>> {
    let mut options = TransferOptions::default();
    let mut paths = Vec::new();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-a" if operation == "pull" => options.archive = true,
            "--sync" if operation == "push" => options.sync = true,
            "-n" if operation == "push" => options.dry_run = true,
            "-q" => options.quiet = true,
            "-Z" => {
                return Err(format!(
                    "{operation} compression options are not supported by the bundled adb client"
                )
                .into());
            }
            "-z" => {
                let _algorithm = args.get(index + 1).ok_or("missing compression algorithm")?;
                return Err(format!(
                    "{operation} compression options are not supported by the bundled adb client"
                )
                .into());
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported {operation} option: {value}").into());
            }
            value => paths.push(value.to_owned()),
        }
        index += 1;
    }
    Ok(TransferRequest { options, paths })
}

trait CompatTransferDevice {
    fn shell(&mut self, command: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn push_file(&mut self, source: &Path, remote: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn pull_file(
        &mut self,
        remote: &str,
        destination: &mut fs::File,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

struct WirelessTransferDevice(adb_client::tcp::ADBDispatchedTCPDevice);

impl CompatTransferDevice for WirelessTransferDevice {
    fn shell(&mut self, command: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        self.0.shell_command(command, Some(&mut output))?;
        Ok(output)
    }

    fn push_file(&mut self, source: &Path, remote: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = fs::File::open(source)?;
        self.0.push(&mut input, &remote)?;
        Ok(())
    }

    fn pull_file(
        &mut self,
        remote: &str,
        destination: &mut fs::File,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.0.pull(&remote, destination)?;
        Ok(())
    }
}

struct USBTransferDevice<'a>(&'a Context);

impl CompatTransferDevice for USBTransferDevice<'_> {
    fn shell(&mut self, command: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        direct_daemon::stream_request_to(self.0, &format!("SHELL\t{command}"), &mut output)?;
        Ok(output)
    }

    fn push_file(&mut self, source: &Path, remote: &str) -> Result<(), Box<dyn std::error::Error>> {
        direct_daemon::request(
            self.0,
            &format!("PUSH\t{}\t{remote}", source.to_string_lossy()),
        )?;
        Ok(())
    }

    fn pull_file(
        &mut self,
        remote: &str,
        destination: &mut fs::File,
    ) -> Result<(), Box<dyn std::error::Error>> {
        direct_daemon::stream_request_to(self.0, &format!("PULL\t{remote}"), destination)?;
        Ok(())
    }
}

struct ServerTransferDevice(ADBServerDevice);

impl CompatTransferDevice for ServerTransferDevice {
    fn shell(&mut self, command: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        let status =
            self.0
                .shell_command(&command, Some(&mut output), Some(&mut std::io::stderr()))?;
        if status.is_some_and(|status| status != 0) {
            return Err(format!("remote shell exited with status {}", status.unwrap()).into());
        }
        Ok(output)
    }

    fn push_file(&mut self, source: &Path, remote: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = fs::File::open(source)?;
        self.0.push(&mut input, &remote)?;
        Ok(())
    }

    fn pull_file(
        &mut self,
        remote: &str,
        destination: &mut fs::File,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.0.pull(&remote, destination)?;
        Ok(())
    }
}

const DEFAULT_ADB_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5037);

fn configured_server_address() -> Result<SocketAddrV4, Box<dyn std::error::Error>> {
    std::env::var("MACANDROIDBRIDGE_ADB_SERVER")
        .unwrap_or_else(|_| DEFAULT_ADB_SERVER.to_string())
        .parse()
        .map_err(Into::into)
}

fn existing_server_devices()
-> Result<Option<(SocketAddrV4, Vec<DeviceLong>)>, Box<dyn std::error::Error>> {
    let mode = std::env::var("MACANDROIDBRIDGE_ADB_MODE").unwrap_or_else(|_| "auto".to_owned());
    if mode == "direct" {
        return Ok(None);
    }
    if !matches!(mode.as_str(), "auto" | "server") {
        return Err(format!("invalid MACANDROIDBRIDGE_ADB_MODE: {mode}").into());
    }
    let address = configured_server_address()?;
    let mut server = ADBServer::new_existing(address);
    match server.devices_long() {
        Ok(devices) => Ok(Some((address, devices))),
        Err(error) if mode == "auto" => {
            if TcpStream::connect_timeout(&SocketAddr::V4(address), Duration::from_millis(250))
                .is_ok()
            {
                Err(format!(
                    "existing ADB server at {address} rejected the compatibility request: {error}"
                )
                .into())
            } else {
                Ok(None)
            }
        }
        Err(error) => {
            Err(format!("existing ADB server at {address} is unavailable: {error}").into())
        }
    }
}

fn server_device(
    address: SocketAddrV4,
    serial: Option<&str>,
    transport_id: Option<u64>,
) -> Result<ADBServerDevice, Box<dyn std::error::Error>> {
    if let Some(id) = transport_id {
        return Ok(ADBServerDevice::new_with_transport_id(
            u32::try_from(id).map_err(|_| "ADB server transport id exceeds u32")?,
            Some(address),
        ));
    }
    Ok(serial.map_or_else(
        || ADBServerDevice::autodetect(Some(address)),
        |serial| ADBServerDevice::new(serial.to_owned(), Some(address)),
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn validate_transfer_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if path.contains(['\n', '\r', '\t', '\0']) {
        return Err("file paths containing control characters are not supported".into());
    }
    Ok(())
}

fn collect_local_entries(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut entries = vec![root.to_path_buf()];
    if fs::symlink_metadata(root)?.file_type().is_dir() {
        for entry in fs::read_dir(root)? {
            entries.extend(collect_local_entries(&entry?.path())?);
        }
    }
    Ok(entries)
}

fn remote_join(base: &str, component: &Path) -> String {
    let relative = component.to_string_lossy();
    if relative.is_empty() {
        base.trim_end_matches('/').to_owned()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), relative)
    }
}

fn remote_file_is_current(
    device: &mut dyn CompatTransferDevice,
    remote: &str,
    metadata: &fs::Metadata,
) -> bool {
    let command = format!("stat -c '%s %Y' -- {}", shell_quote(remote));
    let Ok(output) = device.shell(&command) else {
        return false;
    };
    let value = String::from_utf8_lossy(&output);
    let mut fields = value.split_whitespace();
    let remote_size = fields.next().and_then(|field| field.parse::<u64>().ok());
    let remote_mtime = fields.next().and_then(|field| field.parse::<i64>().ok());
    remote_size == Some(metadata.len())
        && remote_mtime.is_some_and(|mtime| mtime >= metadata.mtime())
}

fn apply_remote_metadata(
    device: &mut dyn CompatTransferDevice,
    remote: &str,
    metadata: &fs::Metadata,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = metadata.mode() & 0o7777;
    device.shell(&format!(
        "touch -m -d @{mtime} -- {path} && chmod {mode:o} -- {path}",
        path = shell_quote(remote),
        mtime = metadata.mtime()
    ))?;
    Ok(())
}

fn push_compatible(
    device: &mut dyn CompatTransferDevice,
    request: TransferRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.paths.len() < 2 {
        return Err("push requires at least one source and a destination".into());
    }
    let mut paths = request.paths;
    let destination = paths.pop().unwrap();
    validate_transfer_path(&destination)?;
    for path in &paths {
        validate_transfer_path(path)?;
    }
    let destination_is_directory = device.shell(&format!(
        "if [ -d {} ]; then printf directory; fi",
        shell_quote(&destination)
    ))? == b"directory";
    let multi = destination_is_directory
        || paths.len() > 1
        || paths
            .iter()
            .any(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()));
    if multi && !request.options.dry_run {
        device.shell(&format!("mkdir -p -- {}", shell_quote(&destination)))?;
    }
    for source in paths {
        let root = Path::new(&source);
        let base = root.file_name().ok_or("invalid local path")?;
        let mut directories = Vec::new();
        for entry in collect_local_entries(root)? {
            validate_transfer_path(&entry.to_string_lossy())?;
            let metadata = fs::symlink_metadata(&entry)?;
            let relative = entry.strip_prefix(root)?;
            let remote = if multi {
                remote_join(&remote_join(&destination, Path::new(base)), relative)
            } else {
                destination.clone()
            };
            if !request.options.quiet {
                println!("{} -> {remote}", entry.display());
            }
            if request.options.dry_run {
                continue;
            }
            if metadata.file_type().is_dir() {
                device.shell(&format!("mkdir -p -- {}", shell_quote(&remote)))?;
                directories.push((remote, metadata));
            } else if metadata.file_type().is_symlink() {
                let target = fs::read_link(&entry)?;
                let parent = Path::new(&remote).parent().ok_or("invalid remote path")?;
                device.shell(&format!(
                    "mkdir -p -- {parent} && rm -f -- {remote} && ln -s -- {target} {remote}",
                    parent = shell_quote(&parent.to_string_lossy()),
                    remote = shell_quote(&remote),
                    target = shell_quote(&target.to_string_lossy())
                ))?;
            } else if metadata.file_type().is_file() {
                if request.options.sync && remote_file_is_current(device, &remote, &metadata) {
                    continue;
                }
                if let Some(parent) = Path::new(&remote).parent() {
                    device.shell(&format!(
                        "mkdir -p -- {}",
                        shell_quote(&parent.to_string_lossy())
                    ))?;
                }
                device.push_file(&entry, &remote)?;
                apply_remote_metadata(device, &remote, &metadata)?;
            }
        }
        // Children modify their parent directory's mtime, so restore directory
        // metadata from the leaves back to the root after all writes finish.
        for (remote, metadata) in directories.into_iter().rev() {
            apply_remote_metadata(device, &remote, &metadata)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RemoteEntry {
    kind: char,
    mode: u32,
    mtime: i64,
    path: String,
}

fn remote_manifest(
    device: &mut dyn CompatTransferDevice,
    source: &str,
) -> Result<Vec<RemoteEntry>, Box<dyn std::error::Error>> {
    validate_transfer_path(source)?;
    let quoted = shell_quote(source);
    let script = format!(
        "find {quoted} -print | while IFS= read -r p; do if [ -L \"$p\" ]; then k=l; elif [ -d \"$p\" ]; then k=d; elif [ -f \"$p\" ]; then k=f; else k=o; fi; mode=$(stat -c '%a' -- \"$p\") || exit; mtime=$(stat -c '%Y' -- \"$p\") || exit; printf '%s\\t%s\\t%s\\t%s\\n' \"$k\" \"$mode\" \"$mtime\" \"$p\"; done"
    );
    let output = device.shell(&script)?;
    let mut entries = Vec::new();
    for line in String::from_utf8(output)?.lines() {
        let fields: Vec<_> = line.splitn(4, '\t').collect();
        if fields.len() != 4 {
            return Err("invalid remote file manifest".into());
        }
        let kind = fields[0].chars().next().ok_or("missing remote file type")?;
        if !matches!(kind, 'f' | 'd' | 'l') {
            continue;
        }
        validate_transfer_path(fields[3])?;
        entries.push(RemoteEntry {
            kind,
            mode: u32::from_str_radix(fields[1], 8)?,
            mtime: fields[2].parse()?,
            path: fields[3].to_owned(),
        });
    }
    if entries.is_empty() {
        return Err(format!("remote path does not exist: {source}").into());
    }
    Ok(entries)
}

fn safe_relative_remote_path<'a>(
    source: &str,
    path: &'a str,
) -> Result<&'a Path, Box<dyn std::error::Error>> {
    let relative = Path::new(path).strip_prefix(Path::new(source))?;
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err("unsafe remote path".into());
    }
    Ok(relative)
}

fn apply_local_metadata(
    path: &Path,
    entry: &RemoteEntry,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::File::open(path)?
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(entry.mtime.max(0) as u64))?;
    fs::set_permissions(path, fs::Permissions::from_mode(entry.mode & 0o7777))?;
    Ok(())
}

fn pull_compatible(
    device: &mut dyn CompatTransferDevice,
    request: TransferRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.paths.len() < 2 {
        return Err("pull requires at least one source and a destination".into());
    }
    let mut paths = request.paths;
    let destination = PathBuf::from(paths.pop().unwrap());
    let multi = paths.len() > 1 || destination.is_dir();
    if multi {
        fs::create_dir_all(&destination)?;
    }
    for source in paths {
        let entries = remote_manifest(device, &source)?;
        let root_is_directory = entries.first().is_some_and(|entry| entry.kind == 'd');
        let base = Path::new(&source)
            .file_name()
            .ok_or("invalid remote path")?;
        let local_root = if multi || root_is_directory {
            destination.join(base)
        } else {
            destination.clone()
        };
        let mut directories = Vec::new();
        for entry in entries {
            let relative = safe_relative_remote_path(&source, &entry.path)?;
            let local = if relative.as_os_str().is_empty() {
                local_root.clone()
            } else {
                local_root.join(relative)
            };
            if !request.options.quiet {
                println!("{} -> {}", entry.path, local.display());
            }
            let safety_root = if multi || root_is_directory || destination.is_dir() {
                destination.as_path()
            } else {
                destination.parent().unwrap_or(Path::new("."))
            };
            check_pull_ancestors(safety_root, &local, entry.kind == 'd')?;
            match entry.kind {
                'd' => {
                    fs::create_dir_all(&local)?;
                    directories.push((local, entry));
                }
                'l' => {
                    if let Some(parent) = local.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let target = String::from_utf8(
                        device.shell(&format!("readlink -- {}", shell_quote(&entry.path)))?,
                    )?;
                    if fs::symlink_metadata(&local).is_ok() {
                        fs::remove_file(&local)?;
                    }
                    std::os::unix::fs::symlink(target.trim_end(), &local)?;
                }
                'f' => {
                    if let Some(parent) = local.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let (temporary, mut output) = create_pull_temporary(&local)?;
                    let result = device.pull_file(&entry.path, &mut output).and_then(|()| {
                        output.sync_all()?;
                        fs::rename(&temporary, &local)?;
                        Ok(())
                    });
                    let _ = fs::remove_file(&temporary);
                    result?;
                    if request.options.archive {
                        apply_local_metadata(&local, &entry)?;
                    }
                }
                _ => {}
            }
        }
        if request.options.archive {
            for (path, entry) in directories.into_iter().rev() {
                apply_local_metadata(&path, &entry)?;
            }
        }
    }
    Ok(())
}

fn sync_compatible(
    device: &mut dyn CompatTransferDevice,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut list_only = false;
    let mut partition = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-l" => list_only = true,
            "-Z" => {
                return Err("sync compression is not supported by the bundled adb client".into());
            }
            "-z" => {
                let _algorithm = args.get(index + 1).ok_or("missing compression algorithm")?;
                return Err("sync compression is not supported by the bundled adb client".into());
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported sync option: {value}").into());
            }
            value => {
                if partition.replace(value.to_owned()).is_some() {
                    return Err("sync accepts at most one partition".into());
                }
            }
        }
        index += 1;
    }
    let product_out = std::env::var_os("ANDROID_PRODUCT_OUT")
        .map(PathBuf::from)
        .ok_or("ANDROID_PRODUCT_OUT is not set")?;
    let selected = partition.as_deref().unwrap_or("all");
    const PARTITIONS: &[&str] = &[
        "data",
        "odm",
        "oem",
        "product",
        "system",
        "system_ext",
        "vendor",
    ];
    let partitions: Vec<&str> = if selected == "all" {
        PARTITIONS.to_vec()
    } else if PARTITIONS.contains(&selected) {
        vec![selected]
    } else {
        return Err(format!("unsupported sync partition: {selected}").into());
    };
    for name in partitions {
        let source_root = product_out.join(name);
        if !source_root.is_dir() {
            if selected == "all" {
                continue;
            }
            return Err(format!("sync source is missing: {}", source_root.display()).into());
        }
        for entry in fs::read_dir(&source_root)? {
            push_compatible(
                device,
                TransferRequest {
                    options: TransferOptions {
                        dry_run: list_only,
                        sync: true,
                        ..TransferOptions::default()
                    },
                    paths: vec![
                        entry?.path().to_string_lossy().into_owned(),
                        format!("/{name}"),
                    ],
                },
            )?;
        }
    }
    Ok(())
}

/// Executes commands that do not need a process-persistent reverse or forward
/// relay over one authenticated Android wireless-debugging connection.
fn create_pull_temporary(local: &Path) -> Result<(PathBuf, fs::File), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut random = fs::File::open("/dev/urandom")?;
    loop {
        let mut bytes = [0u8; 16];
        random.read_exact(&mut bytes)?;
        let path =
            local.with_file_name(format!(".mab-{:032x}.partial", u128::from_ne_bytes(bytes)));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn check_pull_ancestors(
    root: &Path,
    local: &Path,
    directory: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let end = if directory {
        local
    } else {
        local.parent().unwrap_or(root)
    };
    for ancestor in end.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        if fs::symlink_metadata(ancestor).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(format!(
                "refusing to traverse download symlink: {}",
                ancestor.display()
            )
            .into());
        }
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum ForwardRequest<'a> {
    Add(&'a str, &'a str),
    List,
    Remove(&'a str),
    RemoveAll,
}

fn parse_forward_request(
    args: &[String],
) -> Result<Option<ForwardRequest<'_>>, Box<dyn std::error::Error>> {
    match args {
        [command, option] if command == "forward" && option == "--list" => {
            Ok(Some(ForwardRequest::List))
        }
        [command, option, local] if command == "forward" && option == "--remove" => {
            Ok(Some(ForwardRequest::Remove(local)))
        }
        [command, option] if command == "forward" && option == "--remove-all" => {
            Ok(Some(ForwardRequest::RemoveAll))
        }
        [command, local, remote] if command == "forward" && !local.starts_with('-') => {
            Ok(Some(ForwardRequest::Add(local, remote)))
        }
        [command, ..] if command == "forward" => {
            Err("usage: adb forward [--list|--remove LOCAL|--remove-all|LOCAL REMOTE]".into())
        }
        _ => Ok(None),
    }
}

fn run_wireless_forward_command(
    address: SocketAddr,
    key: &Path,
    args: &[String],
) -> Result<bool, Box<dyn std::error::Error>> {
    let context = wireless_forward_daemon::Context { address, key };
    match parse_forward_request(args)? {
        Some(ForwardRequest::Add(local, remote)) => {
            wireless_forward_daemon::request(&context, &format!("FORWARD\t{local}\t{remote}"))?;
        }
        Some(ForwardRequest::List) => {
            print!("{}", wireless_forward_daemon::request(&context, "LIST")?);
        }
        Some(ForwardRequest::Remove(local)) => {
            wireless_forward_daemon::request(&context, &format!("REMOVE\t{local}"))?;
        }
        Some(ForwardRequest::RemoveAll) => {
            wireless_forward_daemon::request(&context, "REMOVE_ALL")?;
        }
        None => return Ok(false),
    }
    Ok(true)
}

fn run_wireless_device_command(
    address: SocketAddr,
    key: &Path,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if run_wireless_forward_command(address, key, args)? {
        return Ok(());
    }
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
        Some("pull") => {
            let request = transfer_paths(args, "pull")?;
            pull_compatible(
                &mut WirelessTransferDevice(device.into_dispatched()),
                request,
            )?;
        }
        Some("push") => {
            let request = transfer_paths(args, "push")?;
            push_compatible(
                &mut WirelessTransferDevice(device.into_dispatched()),
                request,
            )?;
        }
        Some("sync") => {
            sync_compatible(&mut WirelessTransferDevice(device.into_dispatched()), args)?
        }
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
        _ => return Err(format!("unsupported wireless command: {}", args.join(" ")).into()),
    }
    Ok(())
}

fn server_shell_to(
    device: &mut ADBServerDevice,
    command: &str,
    output: &mut dyn std::io::Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = device.shell_command(&command, Some(output), Some(&mut std::io::stderr()))?;
    if let Some(status) = status
        && status != 0
    {
        return Err(format!("remote shell exited with status {status}").into());
    }
    Ok(())
}

fn run_server_device_command(
    address: SocketAddrV4,
    serial: Option<&str>,
    transport_id: Option<u64>,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut device = server_device(address, serial, transport_id)?;
    if let Some(forward) = parse_forward_request(args)? {
        match forward {
            ForwardRequest::Add(local, remote) => {
                // adb_client's server API accepts (remote, local), while the
                // adb CLI syntax is `forward LOCAL REMOTE`.
                device.forward(remote.to_owned(), local.to_owned())?;
            }
            ForwardRequest::Remove(local) => device.forward_remove(local.to_owned())?,
            ForwardRequest::RemoveAll => device.forward_remove_all()?,
            ForwardRequest::List => {
                return Err("forward --list is not yet available through ADB server mode".into());
            }
        }
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("get-state") if args.len() == 1 => println!("device"),
        Some("get-serialno") if args.len() == 1 => {
            if let Some(serial) = serial {
                println!("{serial}");
            } else {
                let mut output = Vec::new();
                server_shell_to(&mut device, "getprop ro.serialno", &mut output)?;
                print!("{}", String::from_utf8(output)?);
            }
        }
        Some("features") if args.len() == 1 => {
            println!(
                "{}",
                device
                    .host_features()?
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        Some("shell") | Some("exec-out") => {
            let mut command_args = args[1..].to_vec();
            while let Some(option) = command_args.first().map(String::as_str) {
                if matches!(option, "-T" | "-t" | "-tt" | "-x" | "--" | "-n") {
                    command_args.remove(0);
                } else {
                    break;
                }
            }
            server_shell_to(&mut device, &command_args.join(" "), &mut std::io::stdout())?;
        }
        Some("pull-stream") if args.len() == 2 => {
            device.pull(&args[1], &mut std::io::stdout())?;
        }
        Some("pull") => {
            let request = transfer_paths(args, "pull")?;
            pull_compatible(&mut ServerTransferDevice(device), request)?;
        }
        Some("push") => {
            let request = transfer_paths(args, "push")?;
            push_compatible(&mut ServerTransferDevice(device), request)?;
        }
        Some("sync") => sync_compatible(&mut ServerTransferDevice(device), args)?,
        Some("install") => {
            let request = parse_install_request(args)?;
            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let remote = format!("/data/local/tmp/mab-server-install-{suffix}.apk");
            let mut input = fs::File::open(&request.source)?;
            device.push(&mut input, &remote)?;
            let user = request
                .user
                .map(|user| format!(" --user {}", shell_quote(&user)))
                .unwrap_or_default();
            let command = format!(
                "pm install {}{user} {}",
                request.flags.join(" "),
                shell_quote(&remote)
            );
            let result = server_shell_to(&mut device, &command, &mut std::io::stdout());
            let _ = server_shell_to(
                &mut device,
                &format!("rm -f -- {}", shell_quote(&remote)),
                &mut std::io::sink(),
            );
            result?;
        }
        Some("uninstall") => {
            let request = parse_uninstall_request(args)?;
            let keep = if request.keep_data { " -k" } else { "" };
            let user = request
                .user
                .map(|user| format!(" --user {}", shell_quote(&user)))
                .unwrap_or_default();
            server_shell_to(
                &mut device,
                &format!("pm uninstall{keep}{user} {}", shell_quote(&request.package)),
                &mut std::io::stdout(),
            )?;
        }
        Some("root") if args.len() == 1 => device.root()?,
        Some("remount") if args.len() == 1 => {
            let _ = device.remount()?;
        }
        Some("reboot") if args.len() <= 2 => {
            let reboot_type = match args.get(1).map(String::as_str) {
                None => RebootType::System,
                Some("bootloader") => RebootType::Bootloader,
                Some("recovery") => RebootType::Recovery,
                Some("sideload") => RebootType::Sideload,
                Some(mode) => return Err(format!("unsupported reboot mode: {mode}").into()),
            };
            device.reboot(reboot_type)?;
        }
        Some("reverse")
            if args.get(1).map(String::as_str) == Some("--remove") && args.len() == 3 =>
        {
            device.reverse_remove(args[2].clone())?;
        }
        Some("reverse")
            if args.get(1).map(String::as_str) == Some("--remove-all") && args.len() == 2 =>
        {
            device.reverse_remove_all()?;
        }
        Some("reverse") if args.len() == 3 => {
            device.reverse(args[1].clone(), args[2].clone())?;
        }
        Some("reverse") if args.get(1).map(String::as_str) == Some("--list") => {
            return Err("reverse --list is not yet available through ADB server mode".into());
        }
        Some("logcat") => {
            let command = if args.len() == 1 {
                "logcat".to_owned()
            } else {
                format!("logcat {}", args[1..].join(" "))
            };
            server_shell_to(&mut device, &command, &mut std::io::stdout())?;
        }
        _ => return Err(format!("unsupported ADB server command: {}", args.join(" ")).into()),
    }
    Ok(())
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
    let mut selected_transport_id = None;
    let mut endpoint = None;
    while args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "-s" | "-t"))
    {
        if args.len() < 2 {
            return Err("missing device selector value".into());
        }
        match args[0].as_str() {
            "-s" if selected_transport_id.is_none() => serial = Some(args[1].clone()),
            "-t" if serial.is_none() => selected_transport_id = Some(args[1].parse::<u64>()?),
            _ => return Err("only one of -s and -t may be specified".into()),
        }
        args.drain(0..2);
    }
    if args.first().map(String::as_str) == Some("usb") {
        args.remove(0);
        if args.as_slice() == ["--list"] {
            let devices = find_all_connected_adb_devices()?;
            println!("Index\tVendor ID\tProduct ID\tLocation ID\tDevice Description");
            println!("-----\t---------\t----------\t-----------\t----------------");
            for (index, device) in devices.iter().enumerate() {
                println!(
                    "#{index}\t{:04x}\t{:04x}\t{:016x}\t{}",
                    device.vendor_id,
                    device.product_id,
                    device.location_id.unwrap_or(0),
                    device.device_description
                );
            }
            return Ok(());
        }
        let mut vendor = None;
        let mut product = None;
        let mut location = None;
        while args.first().is_some_and(|arg| arg.starts_with("--")) && args.len() >= 2 {
            match args[0].as_str() {
                "--vendor-id" => vendor = Some(u16::from_str_radix(&args[1], 16)?),
                "--product-id" => product = Some(u16::from_str_radix(&args[1], 16)?),
                "--location-id" => location = Some(u64::from_str_radix(&args[1], 16)?),
                "--private-key" => {} // App supplies the same key in the environment.
                _ => return Err("unsupported USB option".into()),
            }
            args.drain(0..2);
        }
        endpoint = Some((
            vendor.ok_or("missing vendor")?,
            product.ok_or("missing product")?,
            location,
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
    let server = if endpoint.is_none() {
        existing_server_devices()?
    } else {
        None
    };
    if args.first().map(String::as_str) == Some("server-status") {
        if args.len() != 1 {
            return Err("server-status does not accept arguments".into());
        }
        let (address, _) = server.ok_or("no compatible ADB server is running")?;
        println!("ADB server available at {address}");
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("devices")
        && let Some((_, server_devices)) = &server
    {
        if args.len() > 2 || args.get(1).is_some_and(|option| option != "-l") {
            return Err("usage: adb devices [-l]".into());
        }
        println!("List of devices attached");
        let mut identifiers = BTreeSet::new();
        for device in server_devices {
            identifiers.insert(device.identifier.clone());
            if args.get(1).map(String::as_str) == Some("-l") {
                println!("{device} mab_transport:server");
            } else {
                println!("{}\t{}", device.identifier, device.state);
            }
        }
        // Preserve adb_client-managed wireless endpoints that are not also
        // registered in the developer-owned ADB server.
        for address in wireless_endpoints(&key)? {
            if identifiers.contains(&address.to_string()) {
                continue;
            }
            match connect_wireless(address, &key) {
                Ok(serial) => println!(
                    "{address}\tdevice product:wireless model:{serial} transport_id:{}",
                    stable_transport_id("tcp", &address.to_string())
                ),
                Err(_) => println!(
                    "{address}\toffline transport_id:{}",
                    stable_transport_id("tcp", &address.to_string())
                ),
            }
        }
        return Ok(());
    }
    if args.as_slice() == ["start-server"] && server.is_some() {
        return Ok(());
    }
    if args.as_slice() == ["wait-for-device"]
        && server
            .as_ref()
            .is_some_and(|(_, devices)| !devices.is_empty())
    {
        return Ok(());
    }
    if let Some((address, server_devices)) = &server {
        let matching_server_devices: Vec<_> = server_devices
            .iter()
            .filter(|device| {
                serial
                    .as_ref()
                    .is_none_or(|serial| &device.identifier == serial)
                    && selected_transport_id.is_none_or(|id| u64::from(device.transport_id) == id)
            })
            .collect();
        let server_selected = if serial.is_some() || selected_transport_id.is_some() {
            matching_server_devices.len() == 1
        } else {
            server_devices.len() == 1
        };
        if server_selected {
            return run_server_device_command(
                *address,
                serial.as_deref(),
                selected_transport_id,
                &args,
            );
        }
        if !server_devices.is_empty()
            && serial.is_none()
            && selected_transport_id.is_none()
            && !matches!(
                args.first().map(String::as_str),
                Some("start-server" | "wait-for-device")
            )
        {
            return Err(
                "multiple devices connected through ADB server; select one with -s or -t".into(),
            );
        }
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
    if endpoint.is_none()
        && let Some(transport_id) = selected_transport_id
    {
        if let Some(address) = wireless_endpoints(&key)?
            .into_iter()
            .find(|address| stable_transport_id("tcp", &address.to_string()) == transport_id)
        {
            return run_wireless_device_command(address, &key, &args);
        }
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
                let context = usb_context(&key, &device);
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
            let context = usb_context(&key, &device);
            let details = direct_daemon::request(&context, "DEVICE_INFO")?;
            let mut values = details.lines();
            let identifier = values.next().ok_or("missing serial")?;
            let model = values.next().unwrap_or("").replace(' ', "_");
            let product = values.next().unwrap_or("");
            println!(
                "{identifier}\tdevice product:{product} model:{model} transport_id:{}",
                usb_transport_id(&device)
            );
        }
        for address in wireless_endpoints(&key)? {
            match connect_wireless(address, &key) {
                Ok(serial) => println!(
                    "{address}\tdevice product:wireless model:{serial} transport_id:{}",
                    stable_transport_id("tcp", &address.to_string())
                ),
                Err(_) => println!(
                    "{address}\toffline transport_id:{}",
                    stable_transport_id("tcp", &address.to_string())
                ),
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
            endpoint.is_none_or(|(v, p, location)| {
                device.vendor_id == v
                    && device.product_id == p
                    && location.is_none_or(|value| device.location_id == Some(value))
            })
        })
        .filter(|device| {
            selected_transport_id.is_none_or(|value| usb_transport_id(device) == value)
        })
        .filter(|device| {
            let Some(requested_serial) = serial.as_ref() else {
                return true;
            };
            if device.serial.as_ref() == Some(requested_serial) {
                return true;
            }
            let context = usb_context(&key, device);
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
    let context = usb_context(&key, device);
    if let Some(forward) = parse_forward_request(&args)? {
        match forward {
            ForwardRequest::Add(local, remote) => {
                direct_daemon::request(&context, &format!("FORWARD\t{local}\t{remote}"))?;
            }
            ForwardRequest::List => {
                print!("{}", direct_daemon::request(&context, "FORWARD_LIST")?);
            }
            ForwardRequest::Remove(local) => {
                direct_daemon::request(&context, &format!("FORWARD_REMOVE\t{local}"))?;
            }
            ForwardRequest::RemoveAll => {
                direct_daemon::request(&context, "FORWARD_REMOVE_ALL")?;
            }
        }
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("get-state") => println!("device"),
        Some("get-serialno") => {
            let details = direct_daemon::request(&context, "DEVICE_INFO")?;
            println!("{}", details.lines().next().unwrap_or("unknown"));
        }
        Some("get-devpath") => println!(
            "usb:{:04x}:{:04x}:{:016x}",
            device.vendor_id,
            device.product_id,
            device.location_id.unwrap_or(0)
        ),
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
            let request = transfer_paths(&args, "pull")?;
            pull_compatible(&mut USBTransferDevice(&context), request)?;
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
            let request = transfer_paths(&args, "push")?;
            push_compatible(&mut USBTransferDevice(&context), request)?;
        }
        Some("sync") => sync_compatible(&mut USBTransferDevice(&context), &args)?,
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
        _ => return Err(format!("unsupported direct-USB command: {}", args.join(" ")).into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CompatTransferDevice, ForwardRequest, TransferOptions, TransferRequest,
        check_pull_ancestors, create_pull_temporary, parse_forward_request, push_compatible,
    };

    #[derive(Default)]
    struct TransferMock {
        directory: bool,
        fail_metadata: bool,
        uploaded: Vec<String>,
    }
    impl CompatTransferDevice for TransferMock {
        fn shell(&mut self, command: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            if command.starts_with("if [ -d") {
                return Ok(if self.directory {
                    b"directory".to_vec()
                } else {
                    vec![]
                });
            }
            if self.fail_metadata && command.starts_with("touch ") {
                return Err("remote chmod failed".into());
            }
            Ok(vec![])
        }
        fn push_file(&mut self, _: &Path, remote: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.uploaded.push(remote.to_owned());
            Ok(())
        }
        fn pull_file(
            &mut self,
            _: &str,
            _: &mut fs::File,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unreachable!()
        }
    }

    #[test]
    fn single_file_push_uses_directory_basename_and_reports_metadata_failure() {
        let (source, file) = create_pull_temporary(&std::env::temp_dir().join("source")).unwrap();
        drop(file);
        let mut device = TransferMock {
            directory: true,
            ..Default::default()
        };
        let request = || TransferRequest {
            options: TransferOptions {
                quiet: true,
                ..Default::default()
            },
            paths: vec![source.to_string_lossy().into_owned(), "/system".into()],
        };
        push_compatible(&mut device, request()).unwrap();
        assert_eq!(
            device.uploaded[0],
            format!("/system/{}", source.file_name().unwrap().to_str().unwrap())
        );
        device.fail_metadata = true;
        assert!(push_compatible(&mut device, request()).is_err());
        fs::remove_file(source).unwrap();
    }

    #[test]
    fn pull_temporary_is_unique_and_symlink_ancestors_are_rejected() {
        let base = std::env::temp_dir().join("download");
        let (first, file) = create_pull_temporary(&base).unwrap();
        drop(file);
        let (second, file) = create_pull_temporary(&base).unwrap();
        drop(file);
        assert_ne!(first, second);
        fs::remove_file(&first).unwrap();
        symlink(std::env::temp_dir(), &first).unwrap();
        assert!(check_pull_ancestors(&first, &first.join("outside"), false).is_err());
        assert!(check_pull_ancestors(&first, &first, true).is_err());
        fs::remove_file(first).unwrap();
        fs::remove_file(second).unwrap();
    }
    use super::{
        collect_local_entries, parse_install_request, parse_uninstall_request, remote_join,
        safe_relative_remote_path, stable_transport_id, transfer_paths,
    };
    use std::{fs, os::unix::fs::symlink, path::Path};

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn forward_management_flags_are_not_parsed_as_additions() {
        assert_eq!(
            parse_forward_request(&values(&["forward", "--remove", "tcp:1234"])).unwrap(),
            Some(ForwardRequest::Remove("tcp:1234"))
        );
        assert_eq!(
            parse_forward_request(&values(&["forward", "--remove-all"])).unwrap(),
            Some(ForwardRequest::RemoveAll)
        );
        assert_eq!(
            parse_forward_request(&values(&["forward", "tcp:1234", "tcp:4321"])).unwrap(),
            Some(ForwardRequest::Add("tcp:1234", "tcp:4321"))
        );
        assert!(parse_forward_request(&values(&["forward", "--remove", "a", "b"])).is_err());
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

    #[test]
    fn transport_ids_are_stable_and_namespaced() {
        let usb = stable_transport_id("usb", "0000000001100000");
        assert_eq!(usb, stable_transport_id("usb", "0000000001100000"));
        assert_ne!(usb, stable_transport_id("usb", "0000000001200000"));
        assert_ne!(usb, stable_transport_id("tcp", "0000000001100000"));
        assert_ne!(usb, 0);
    }

    #[test]
    fn transfer_compression_options_are_rejected_with_their_values() {
        assert!(transfer_paths(&values(&["push", "-z", "any", "a", "/data/a"]), "push").is_err());
        assert!(transfer_paths(&values(&["pull", "-Z", "/data/a", "a"]), "pull").is_err());
        let request = transfer_paths(
            &values(&["push", "--sync", "-n", "-q", "a", "/data/a"]),
            "push",
        )
        .unwrap();
        assert_eq!(request.paths, ["a", "/data/a"]);
        assert!(request.options.sync);
        assert!(request.options.dry_run);
        assert!(request.options.quiet);
        let request = transfer_paths(&values(&["pull", "-a", "/data/a", "a"]), "pull").unwrap();
        assert!(request.options.archive);
    }

    #[test]
    fn local_walk_keeps_empty_directories_and_does_not_follow_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "mab-transfer-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("file"), b"data").unwrap();
        symlink("empty", root.join("link")).unwrap();
        let entries = collect_local_entries(&root).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries.contains(&root.join("empty")));
        assert!(entries.contains(&root.join("link")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_paths_cannot_escape_the_local_destination() {
        assert_eq!(
            safe_relative_remote_path("/sdcard/source", "/sdcard/source/dir/file").unwrap(),
            Path::new("dir/file")
        );
        assert!(safe_relative_remote_path("/sdcard/source", "/sdcard/source/../secret").is_err());
        assert_eq!(
            remote_join("/sdcard/target/", Path::new("dir/file")),
            "/sdcard/target/dir/file"
        );
    }
}
