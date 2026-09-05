//! Small local control plane for the direct-USB transport.
//!
//! Unlike platform-tools, the direct client cannot reopen the macOS USB ADB
//! interface for every command. This daemon is deliberately local-only and
//! keeps the authenticated `ADBUSBDevice` alive for the app process.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    sync::Arc,
    time::{Duration, Instant},
};

use adb_client::usb::{ADBDispatchedUSBDevice, ADBUSBDevice};

pub(crate) struct Context {
    pub key: PathBuf,
    pub vendor: u16,
    pub product: u16,
}


pub(crate) fn socket_path(context: &Context) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Darwin sockaddr_un only permits roughly 104 bytes. App Support paths
    // routinely exceed that, so derive a short, per-key path in /private/tmp.
    // The socket is mode 0600 and its deterministic key hash keeps separate
    // sandbox identities from sharing a transport.
    let hash = context.key
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |value, byte| {
            (value ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    let directory = std::env::temp_dir().join(format!("mab3-{hash:016x}"));
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    Ok(directory.join(format!("{:04x}{:04x}.sock", context.vendor, context.product)))
}

pub(crate) fn ensure_running(context: &Context) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path(context)?;
    let lock = fs::OpenOptions::new().create(true).truncate(false).write(true).open(socket.with_extension("lock"))?;
    lock.lock()?;
    if let Ok(mut probe) = UnixStream::connect(&socket) {
        probe.write_all(&0u32.to_be_bytes())?;
        probe.shutdown(std::net::Shutdown::Write)?;
        let mut response = [0u8; 4];
        // A healthy daemon responds with an error for an empty request; the
        // important signal is that the control socket is serviced.
        if probe.read_exact(&mut response).is_ok() {
            return Ok(());
        }
        let _ = fs::remove_file(&socket);
    }
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    Command::new(std::env::current_exe()?)
        .env("ADB_CLI_DIRECT_DAEMON", "1")
        .env("MACANDROIDBRIDGE_ADB_KEY", &context.key)
        .env("ADB_CLI_VENDOR", context.vendor.to_string())
        .env("ADB_CLI_PRODUCT", context.product.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::OpenOptions::new().create(true).truncate(true).write(true).open(socket.with_extension("log"))?)
        .spawn()?;
    for _ in 0..80 {
        if UnixStream::connect(&socket).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("direct USB daemon did not become ready: {}", fs::read_to_string(socket.with_extension("log")).unwrap_or_default()).into())
}

pub(crate) fn request(context: &Context, request: &str) -> Result<String, Box<dyn std::error::Error>> {
    ensure_running(context)?;
    let mut stream = UnixStream::connect(socket_path(context)?)?;
    stream.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
    stream.write_all(request.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response = response.strip_prefix("OK\n").ok_or_else(|| {
        response.strip_prefix("ERR\t").map_or_else(
            || format!("invalid daemon response: {response}"),
            |message| format!("direct USB daemon: {message}"),
        )
    })?;
    Ok(response.to_owned())
}

pub(crate) fn stream_request(context: &Context, request: &str) -> Result<(), Box<dyn std::error::Error>> {
    stream_request_to(context, request, &mut std::io::stdout().lock())
}

pub(crate) fn stream_request_to(context: &Context, request: &str, output: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    ensure_running(context)?;
    let mut stream = UnixStream::connect(socket_path(context)?)?;
    stream.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
    stream.write_all(request.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    decode_stream(&mut BufReader::new(stream), output)
}

fn decode_stream(reader: &mut impl BufRead, output: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    let mut status = String::new();
    reader.read_line(&mut status)?;
    if status != "OK\n" { return Err(status.into()); }
    loop {
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 { break; }
        if length > 1024 * 1024 { return Err("oversized output frame".into()); }
        let mut data = vec![0; length];
        reader.read_exact(&mut data)?;
        output.write_all(&data)?;
    }
    let mut result = String::new();
    reader.read_to_string(&mut result)?;
    if result == "OK\n" { Ok(()) } else { Err(result.into()) }
}

struct FramedWriter<'a>(&'a mut UnixStream);
impl Write for FramedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() { return Ok(0); }
        for chunk in bytes.chunks(64 * 1024) {
            self.0.write_all(&(chunk.len() as u32).to_be_bytes())?;
            self.0.write_all(chunk)?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { self.0.flush() }
}

fn stream_operation(stream: &mut UnixStream, operation: impl FnOnce(&mut dyn Write) -> adb_client::Result<()>) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_all(b"OK\n")?;
    let result = operation(&mut FramedWriter(stream));
    stream.write_all(&0u32.to_be_bytes())?;
    match result {
        Ok(()) => stream.write_all(b"OK\n")?,
        Err(error) => writeln!(stream, "ERR\t{error}")?,
    }
    Ok(())
}

pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    // The compatibility daemon bypasses clap's normal logger setup.
    let _ = env_logger::try_init();
    let context = Context {
        key: std::env::var_os("MACANDROIDBRIDGE_ADB_KEY").map(PathBuf::from).ok_or("missing key")?,
        vendor: std::env::var("ADB_CLI_VENDOR")?.parse()?,
        product: std::env::var("ADB_CLI_PRODUCT")?.parse()?,
    };
    let socket = socket_path(&context)?;
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let device = Arc::new(ADBUSBDevice::new_with_custom_private_key(context.vendor, context.product, context.key)?.into_dispatched());
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut last_request = Instant::now();
    while device.is_alive() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Darwin accepts inherit O_NONBLOCK from the listener. Service
                // streams need blocking backpressure for large binary downloads.
                stream.set_nonblocking(false)?;
                last_request = Instant::now();
                let device = Arc::clone(&device);
                thread::spawn(move || {
                    if let Err(error) = handle(device, &mut stream) {
                        let _ = writeln!(stream, "ERR\t{error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // Release USB after the app stops using us. Long-running shell
                // requests hold another Arc, so active mirrors never time out.
                if Arc::strong_count(&device) == 1 && last_request.elapsed() > Duration::from_secs(60) { break; }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
    let _ = fs::remove_file(socket);
    Ok(())
}

fn handle(
    device: Arc<ADBDispatchedUSBDevice>,
    stream: &mut UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 1024 * 1024 { return Err("request exceeds 1 MiB".into()); }
    let mut request = vec![0; length];
    stream.read_exact(&mut request)?;
    let request = String::from_utf8(request)?;
    let mut fields = request.split('\t');
    let command = fields.next().ok_or("empty daemon request")?;
    let mut output = Vec::new();
    match command {
        "SHELL" => {
            let shell = request.split_once('\t').ok_or("missing shell command")?.1;
            return stream_operation(stream, |output| device.shell_command(shell, Some(output)));
        }
        "EXEC" => {
            let command = request.split_once('\t').ok_or("missing exec command")?.1;
            return stream_operation(stream, |output| device.exec_out(command, output));
        }
        "PULL" => {
            let path = request.split_once('\t').ok_or("missing pull path")?.1;
            return stream_operation(stream, |output| device.pull(path, output));
        }
        "INSTALL" => {
            let source = fields.next().ok_or("missing APK")?;
            let flags = fields.next().unwrap_or("");
            let user = fields.next().unwrap_or("");
            if !flags.split_whitespace().all(|flag| matches!(flag, "-r" | "-g" | "-d")) {
                return Err("unsupported install options".into());
            }
            if !user.is_empty() && !user.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid install user".into());
            }
            let suffix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
            let remote = format!("/data/local/tmp/mab-install-{}-{suffix}.apk", std::process::id());
            let result = (|| -> adb_client::Result<()> {
                let mut input = fs::File::open(source)?;
                device.push(&mut input, &remote)?;
                let user_flag = if user.is_empty() { String::new() } else { format!(" --user {user}") };
                device.shell_command(&format!("pm install {flags}{user_flag} {remote}"), Some(&mut output))
            })();
            let _ = device.shell_command(&format!("rm -f {remote}"), None);
            result?;
            if !String::from_utf8_lossy(&output).lines().any(|line| line.trim() == "Success") {
                return Err(String::from_utf8_lossy(&output).into_owned().into());
            }
        }
        "UNINSTALL" => {
            let keep = fields.next().ok_or("missing uninstall option")?;
            let user = fields.next().ok_or("missing uninstall user")?;
            let package = fields.next().ok_or("missing package")?;
            if (keep != "" && keep != "-k") || package.is_empty()
                || !package.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_') {
                return Err("invalid uninstall request".into());
            }
            if !user.is_empty() && !user.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid uninstall user".into());
            }
            let user_flag = if user.is_empty() { String::new() } else { format!(" --user {user}") };
            device.shell_command(&format!("pm uninstall {keep}{user_flag} {package}"), Some(&mut output))?;
            if !String::from_utf8_lossy(&output).lines().any(|line| line.trim() == "Success") {
                return Err(String::from_utf8_lossy(&output).into_owned().into());
            }
        }
        "PING" => {}
        "PUSH" => {
            let source = fields.next().ok_or("missing push source")?;
            let destination = fields.next().ok_or("missing push destination")?;
            let mut input = fs::File::open(source)?;
            device.push(&mut input, destination)?;
        }
        "REVERSE" => {
            let remote = fields.next().ok_or("missing reverse remote")?;
            let local = fields.next().ok_or("missing reverse local")?;
            device.reverse_forward(remote.to_owned(), local.to_owned())?;
        }
        "REVERSE_REMOVE" => {
            let remote = fields.next().ok_or("missing reverse remote")?;
            device.remove_reverse_forward(remote.to_owned())?;
        }
        "REVERSE_LIST" => {
            for (remote, local) in device.reverse_routes()? {
                output.extend_from_slice(format!("{remote} {local}\n").as_bytes());
            }
        }
        "REVERSE_REMOVE_ALL" => {
            device.remove_all_reverse_routes()?;
        }
        "FORWARD" => {
            let local = fields.next().ok_or("missing local forward endpoint")?.to_owned();
            let remote = fields.next().ok_or("missing remote forward endpoint")?.to_owned();
            let device = Arc::clone(&device);
            stream.write_all(b"OK\n")?;
            std::thread::spawn(move || {
                if let Err(error) = device.serve_forward(local, remote) {
                    log::debug!("ADB forward listener ended: {error}");
                }
            });
            return Ok(());
        }
        "FORWARD_LIST" => {
            for (local, remote) in device.forward_routes() {
                output.extend_from_slice(format!("{local} {remote}\n").as_bytes());
            }
        }
        "FORWARD_REMOVE" => {
            let local = fields.next().ok_or("missing local forward endpoint")?;
            if !device.remove_forward(local) { return Err("forward rule not found".into()); }
        }
        "ROOT" => {
            device.root()?;
        }
        "REMOUNT" => {
            device.remount()?;
        }
        "DEVICE_INFO" => {
            for property in ["ro.serialno", "ro.product.model", "ro.build.product"] {
                let mut value = Vec::new();
                device.shell_command(&format!("getprop {property}"), Some(&mut value))?;
                output.extend_from_slice(String::from_utf8(value)?.trim().as_bytes());
                output.push(b'\n');
            }
        }
        _ => return Err(format!("unsupported daemon request: {command}").into()),
    }
    stream.write_all(b"OK\n")?;
    stream.write_all(&output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_binary_stream_applies_backpressure_without_truncation() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let bytes: Vec<u8> = (0..2 * 1024 * 1024).map(|index| (index % 251) as u8).collect();
        let expected = bytes.clone();
        let writer = thread::spawn(move || {
            stream_operation(&mut sender, |output| { output.write_all(&bytes)?; Ok(()) }).unwrap();
        });
        let mut actual = Vec::new();
        decode_stream(&mut BufReader::new(receiver), &mut actual).unwrap();
        writer.join().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn binary_output_preserves_bytes_and_propagates_terminal_errors() {
        let bytes = [0, 255, b'\n', b'O', b'K'];
        let mut framed = b"OK\n".to_vec();
        framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        framed.extend_from_slice(&bytes);
        framed.extend_from_slice(&0u32.to_be_bytes());
        let mut success = framed.clone();
        success.extend_from_slice(b"OK\n");
        let mut output = Vec::new();
        decode_stream(&mut std::io::Cursor::new(success), &mut output).unwrap();
        assert_eq!(output, bytes);
        framed.extend_from_slice(b"ERR\tremote failed\n");
        assert!(decode_stream(&mut std::io::Cursor::new(framed), &mut Vec::new()).is_err());
    }
}
