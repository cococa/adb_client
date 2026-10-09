//! Deadline-aware local IPC for macOS and other Unix hosts.
//!
//! Darwin rejects `SO_RCVTIMEO`/`SO_SNDTIMEO` for `AF_UNIX` sockets. Keep the
//! socket nonblocking and turn `WouldBlock` into an inactivity deadline instead.

use std::{
    io::{self, Read, Write},
    os::unix::{io::AsRawFd, net::UnixStream},
    time::{Duration, Instant},
};

pub(crate) struct DeadlineUnixStream {
    stream: UnixStream,
    timeout: Duration,
}

impl DeadlineUnixStream {
    pub(crate) fn new(stream: UnixStream, timeout: Duration) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self { stream, timeout })
    }

    pub(crate) fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub(crate) fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.stream.shutdown(how)
    }

    /// Blocks until the socket is ready for `events` or the deadline passes.
    /// Darwin's 8 KiB local socket buffer fills and drains many times per
    /// transfer frame, so sleeping a fixed interval here caps file transfers
    /// at a few MiB/s.
    fn wait(&self, events: libc::c_short, deadline: Instant) -> io::Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local control socket timed out",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events,
            revents: 0,
        };
        // Round up so a sub-millisecond remainder cannot become a busy loop.
        let timeout = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as libc::c_int;
        // SAFETY: `descriptor` is one valid pollfd that outlives the call.
        if unsafe { libc::poll(&mut descriptor, 1, timeout) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        // Readiness, hang-up and errors are all reported by the retried call.
        Ok(())
    }
}

impl Read for DeadlineUnixStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.stream.read(output) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN, deadline)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineUnixStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.stream.write(input) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT, deadline)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn idle_read_reaches_deadline() {
        let (_writer, reader) = UnixStream::pair().unwrap();
        let mut reader = DeadlineUnixStream::new(reader, Duration::from_millis(20)).unwrap();
        let error = reader.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// Each direction moves 8 MiB in 64 KiB frames through the default 8 KiB
    /// socket buffer. Sleeping on every full or empty buffer took over two
    /// seconds for this; waiting for readiness takes a few milliseconds.
    #[test]
    fn framed_transfer_does_not_sleep_per_buffer() {
        const FRAME: usize = 64 * 1024;
        const FRAMES: usize = 128;
        let limit = Duration::from_secs(1);

        let (mut app, daemon) = UnixStream::pair().unwrap();
        let mut daemon = DeadlineUnixStream::new(daemon, Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        let writer = thread::spawn(move || {
            let frame = vec![7u8; FRAME];
            for _ in 0..FRAMES {
                app.write_all(&(FRAME as u32).to_be_bytes()).unwrap();
                app.write_all(&frame).unwrap();
            }
        });
        let mut frame = vec![0u8; FRAME];
        for _ in 0..FRAMES {
            let mut length = [0u8; 4];
            daemon.read_exact(&mut length).unwrap();
            daemon.read_exact(&mut frame).unwrap();
        }
        writer.join().unwrap();
        assert!(
            started.elapsed() < limit,
            "upload took {:?}",
            started.elapsed()
        );

        let (mut app, daemon) = UnixStream::pair().unwrap();
        let mut daemon = DeadlineUnixStream::new(daemon, Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        let writer = thread::spawn(move || {
            let frame = vec![7u8; FRAME];
            for _ in 0..FRAMES {
                daemon.write_all(&(FRAME as u32).to_be_bytes()).unwrap();
                daemon.write_all(&frame).unwrap();
            }
        });
        let mut frame = vec![0u8; FRAME];
        for _ in 0..FRAMES {
            let mut length = [0u8; 4];
            app.read_exact(&mut length).unwrap();
            app.read_exact(&mut frame).unwrap();
        }
        writer.join().unwrap();
        assert!(
            started.elapsed() < limit,
            "download took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn available_data_is_not_delayed() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.write_all(b"ready").unwrap();
        let mut reader = DeadlineUnixStream::new(reader, Duration::from_millis(20)).unwrap();
        let mut output = [0; 5];
        reader.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"ready");
    }
}
