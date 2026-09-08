//! Local control plane for persistent wireless ADB forward rules.

use std::{
    fs,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use adb_client::tcp::{ADBDispatchedTCPDevice, ADBTcpDevice};

pub(crate) struct Context<'a> {
    pub address: SocketAddr,
    pub key: &'a Path,
}

fn hash_bytes<'a>(bytes: impl Iterator<Item = &'a u8>) -> u64 {
    bytes.fold(0xcbf2_9ce4_8422_2325u64, |value, byte| {
        (value ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn socket_path(context: &Context<'_>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let identity = format!("{}\0{}", context.key.display(), context.address);
    let hash = hash_bytes(identity.as_bytes().iter());
    Ok(std::env::temp_dir().join(format!("mabw-{hash:016x}.sock")))
}

fn ensure_running(context: &Context<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let socket = socket_path(context)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(socket.with_extension("lock"))?;
    lock.lock()?;
    if request_once(&socket, "PING").is_ok() {
        return Ok(());
    }
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    Command::new(std::env::current_exe()?)
        .env("ADB_CLI_WIRELESS_FORWARD_DAEMON", "1")
        .env("MACANDROIDBRIDGE_ADB_KEY", context.key)
        .env("ADB_CLI_WIRELESS_ADDRESS", context.address.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(socket.with_extension("log"))?,
        )
        .spawn()?;
    for _ in 0..100 {
        if request_once(&socket, "PING").is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!(
        "wireless forward daemon did not become ready: {}",
        fs::read_to_string(socket.with_extension("log")).unwrap_or_default()
    )
    .into())
}

pub(crate) fn request(
    context: &Context<'_>,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    ensure_running(context)?;
    request_once(&socket_path(context)?, request)
}

fn request_once(socket: &Path, request: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket)?;
    // macOS returns EINVAL for SO_RCVTIMEO/SO_SNDTIMEO on AF_UNIX.
    #[cfg(not(target_os = "macos"))]
    {
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    }
    stream.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
    stream.write_all(request.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    response
        .strip_prefix("OK\n")
        .map(str::to_owned)
        .ok_or_else(|| response.trim().to_owned().into())
}

pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    let key = std::env::var_os("MACANDROIDBRIDGE_ADB_KEY")
        .map(PathBuf::from)
        .ok_or("missing key")?;
    let address: SocketAddr = std::env::var("ADB_CLI_WIRELESS_ADDRESS")?.parse()?;
    let context = Context { address, key: &key };
    let socket = socket_path(&context)?;
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let device =
        Arc::new(ADBTcpDevice::new_with_custom_private_key(address, &key)?.into_dispatched());
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut last_request = Instant::now();
    while device.is_alive() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                #[cfg(not(target_os = "macos"))]
                {
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                }
                last_request = Instant::now();
                let device = Arc::clone(&device);
                thread::spawn(move || {
                    if let Err(error) = handle(device, &mut stream) {
                        let _ = writeln!(stream, "ERR\t{error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Arc::strong_count(&device) == 1
                    && last_request.elapsed() > Duration::from_secs(60)
                {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
    let _ = fs::remove_file(socket);
    Ok(())
}

fn handle(
    device: Arc<ADBDispatchedTCPDevice>,
    stream: &mut UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 64 * 1024 {
        return Err("request too large".into());
    }
    let mut request = vec![0; length];
    stream.read_exact(&mut request)?;
    let request = String::from_utf8(request)?;
    let mut fields = request.split('\t');
    match fields.next().ok_or("empty request")? {
        "PING" => {}
        "FORWARD" => {
            let local = fields.next().ok_or("missing local endpoint")?.to_owned();
            let remote = fields.next().ok_or("missing remote endpoint")?.to_owned();
            if fields.next().is_some() {
                return Err("invalid forward request".into());
            }
            let listener_device = Arc::clone(&device);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            thread::spawn(move || {
                if let Err(error) = listener_device.serve_forward_ready(local, remote, ready_tx) {
                    log::debug!("wireless ADB forward listener ended: {error}");
                }
            });
            ready_rx.recv_timeout(Duration::from_secs(2))??;
            stream.write_all(b"OK\n")?;
            return Ok(());
        }
        "LIST" => {
            stream.write_all(b"OK\n")?;
            for (local, remote) in device.forward_routes() {
                writeln!(stream, "{local} {remote}")?;
            }
            return Ok(());
        }
        "REMOVE" => {
            if !device.remove_forward(fields.next().ok_or("missing local endpoint")?) {
                return Err("forward rule not found".into());
            }
        }
        "REMOVE_ALL" => {
            device.remove_all_forwards();
        }
        command => return Err(format!("unsupported wireless daemon request: {command}").into()),
    }
    stream.write_all(b"OK\n")?;
    Ok(())
}
