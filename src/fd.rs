//! Datagram I/O on the routing sockets of Linux and macOS.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

/// Sends one routing message, which the kernel takes whole or not at all.
pub(crate) fn send(fd: BorrowedFd<'_>, message: &[u8]) -> io::Result<()> {
    loop {
        match syscall!(write(
            fd.as_raw_fd(),
            message.as_ptr().cast(),
            message.len()
        )) {
            Ok(n) if n as usize == message.len() => return Ok(()),
            Ok(n) => {
                return Err(io::Error::other(format!(
                    "routing socket took {n} of {} bytes",
                    message.len()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Receives one datagram into `buf` and returns its length.
pub(crate) fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match syscall!(read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result.map(|n| n as usize),
        }
    }
}
