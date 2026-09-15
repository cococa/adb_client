//! Deadline-aware local IPC for macOS and other Unix hosts.
//!
//! Darwin rejects `SO_RCVTIMEO`/`SO_SNDTIMEO` for `AF_UNIX` sockets. Keep the
//! socket nonblocking and turn `WouldBlock` into an inactivity deadline instead.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
};

const RETRY_INTERVAL: Duration = Duration::from_millis(2);

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

    fn wait(deadline: Instant) -> io::Result<()> {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local control socket timed out",
            ));
        }
        thread::sleep(RETRY_INTERVAL.min(deadline.saturating_duration_since(now)));
        Ok(())
    }
}

impl Read for DeadlineUnixStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.stream.read(output) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Self::wait(deadline)?,
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
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Self::wait(deadline)?,
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

    #[test]
    fn idle_read_reaches_deadline() {
        let (_writer, reader) = UnixStream::pair().unwrap();
        let mut reader = DeadlineUnixStream::new(reader, Duration::from_millis(20)).unwrap();
        let error = reader.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
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
