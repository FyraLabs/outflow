use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, trace};
use windows::{
    Win32::Networking::WinSock::{SEND_RECV_FLAGS, SOCKET_ERROR, WSAGetLastError, send},
    Win32::Storage::FileSystem::ReadFile,
    Win32::System::Pipes::PeekNamedPipe,
};

use crate::Args;

pub fn run_unidirectional_forwarding(
    pipe: windows::Win32::Foundation::HANDLE,
    sock: windows::Win32::Networking::WinSock::SOCKET,
    running: Arc<AtomicBool>,
    args: &Args,
) -> u64 {
    unsafe {
        let mut buffer = vec![0u8; args.buffer_size];
        let mut total_bytes_forwarded = 0u64;

        info!("Starting unidirectional data forwarding (pipe -> socket)...");

        // Data forwarding loop - pipe to socket only
        while running.load(Ordering::SeqCst) {
            // Check if data is available before reading (non-blocking approach)
            let mut bytes_available = 0u32;
            let peek_result = PeekNamedPipe(pipe, None, 0, None, Some(&mut bytes_available), None);

            // If peek failed or no data available, sleep briefly and continue
            if peek_result.is_err() || bytes_available == 0 {
                std::thread::sleep(std::time::Duration::from_micros(args.poll_interval));
                continue;
            }

            let mut read = 0u32;
            let result = ReadFile(pipe, Some(&mut buffer), Some(&mut read), None);

            match result {
                Ok(()) if read > 0 => {
                    trace!("Read {} bytes from named pipe", read);

                    // Handle potentially partial sends in non-blocking mode
                    let mut bytes_to_send = read as usize;
                    let mut offset = 0;

                    while bytes_to_send > 0 {
                        let bytes_sent = send(
                            sock,
                            &buffer[offset..offset + bytes_to_send],
                            SEND_RECV_FLAGS(0),
                        );
                        if bytes_sent == SOCKET_ERROR {
                            let error = WSAGetLastError();
                            if error.0 == 10035 {
                                // WSAEWOULDBLOCK
                                // Socket would block, wait a bit and try again
                                std::thread::sleep(std::time::Duration::from_micros(10));
                                continue;
                            } else {
                                debug!("Socket send failed with error {}", error.0);
                                return total_bytes_forwarded;
                            }
                        } else {
                            let sent = bytes_sent as usize;
                            offset += sent;
                            bytes_to_send -= sent;
                            trace!("Sent {} bytes to socket", sent);
                        }
                    }

                    if bytes_to_send > 0 {
                        debug!("Failed to send all data, {} bytes remaining", bytes_to_send);
                        return total_bytes_forwarded;
                    }

                    total_bytes_forwarded += read as u64;
                    trace!(
                        "Sent {} bytes to socket (total: {} bytes)",
                        read, total_bytes_forwarded
                    );
                }
                _ => {
                    debug!("Named pipe read failed or returned 0 bytes, ending forwarding");
                    return total_bytes_forwarded;
                }
            }
        }

        total_bytes_forwarded
    }
}
