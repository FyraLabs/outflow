use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, trace};
use windows::{
    Win32::Networking::WinSock::{SEND_RECV_FLAGS, SOCKET_ERROR, WSAGetLastError, recv, send},
    Win32::Storage::FileSystem::{ReadFile, WriteFile},
    Win32::System::Pipes::PeekNamedPipe,
};

use crate::Args;

pub fn run_bidirectional_forwarding(
    pipe: windows::Win32::Foundation::HANDLE,
    sock: windows::Win32::Networking::WinSock::SOCKET,
    running: Arc<AtomicBool>,
    args: &Args,
) -> u64 {
    unsafe {
        let mut pipe_buffer = vec![0u8; args.buffer_size];
        let mut socket_buffer = vec![0u8; args.buffer_size];
        let mut total_bytes_forwarded = 0u64;

        info!("Starting bidirectional data forwarding...");

        while running.load(Ordering::SeqCst) {
            let mut data_transferred = false;

            // Check for data from pipe to socket
            let mut bytes_available = 0u32;
            let peek_result = PeekNamedPipe(pipe, None, 0, None, Some(&mut bytes_available), None);

            if peek_result.is_ok() && bytes_available > 0 {
                let mut read = 0u32;
                let result = ReadFile(pipe, Some(&mut pipe_buffer), Some(&mut read), None);

                if let Ok(()) = result {
                    if read > 0 {
                        trace!("Read {} bytes from named pipe", read);

                        // Send to socket with partial send handling
                        let mut bytes_to_send = read as usize;
                        let mut offset = 0;

                        while bytes_to_send > 0 {
                            let bytes_sent = send(
                                sock,
                                &pipe_buffer[offset..offset + bytes_to_send],
                                SEND_RECV_FLAGS(0),
                            );
                            if bytes_sent == SOCKET_ERROR {
                                let error = WSAGetLastError();
                                if error.0 == 10035 {
                                    // WSAEWOULDBLOCK
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

                        total_bytes_forwarded += read as u64;
                        trace!("Forwarded {} bytes: pipe -> socket", read);
                        data_transferred = true;
                    }
                }
            }

            // Check for data from socket to pipe
            let bytes_received = recv(sock, &mut socket_buffer, SEND_RECV_FLAGS(0));

            if bytes_received > 0 {
                trace!("Received {} bytes from socket", bytes_received);

                // Write to pipe with partial write handling
                let mut bytes_to_write = bytes_received as usize;
                let mut offset = 0;

                while bytes_to_write > 0 {
                    let mut written = 0u32;
                    let result = WriteFile(
                        pipe,
                        Some(&socket_buffer[offset..offset + bytes_to_write]),
                        Some(&mut written),
                        None,
                    );

                    if result.is_ok() && written > 0 {
                        offset += written as usize;
                        bytes_to_write -= written as usize;
                        trace!("Wrote {} bytes to pipe", written);
                    } else {
                        debug!("Pipe write failed or wrote 0 bytes");
                        return total_bytes_forwarded;
                    }
                }

                total_bytes_forwarded += bytes_received as u64;
                trace!("Forwarded {} bytes: socket -> pipe", bytes_received);
                data_transferred = true;
            } else if bytes_received == SOCKET_ERROR {
                let error = WSAGetLastError();
                if error.0 != 10035 {
                    // Not WSAEWOULDBLOCK, real error
                    debug!("Socket recv failed with error {}", error.0);
                    return total_bytes_forwarded;
                }
            }

            // If no data was transferred in this iteration, sleep briefly
            if !data_transferred {
                std::thread::sleep(std::time::Duration::from_micros(args.poll_interval));
            }
        }

        total_bytes_forwarded
    }
}
