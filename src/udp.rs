use std::ffi::CString;
use std::mem;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, trace};
use windows::{
    Win32::Foundation::INVALID_HANDLE_VALUE,
    Win32::Networking::WinSock::{
        AF_INET, SEND_RECV_FLAGS, SOCK_DGRAM, SOCKADDR_IN,
        SOCKET_ERROR, WSACleanup, WSADATA, WSAGetLastError, WSAStartup, closesocket,
        recv, sendto, socket,
    },
    Win32::Storage::FileSystem::{
        CreateFileA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        OPEN_EXISTING, ReadFile, WriteFile,
    },
    Win32::System::Pipes::PeekNamedPipe,
    core::PCSTR,
};

use crate::{Args, set_socket_nonblocking};

pub fn run_udp_mode(pipe_name: &CString, running: Arc<AtomicBool>, args: &Args) {
    unsafe {
        // Connect to Wine named pipe
        info!("Attempting to connect to named pipe...");
        info!(
            "Will retry indefinitely until pipe '{}' becomes available",
            pipe_name.to_string_lossy()
        );
        let mut retry_count = 0u32;
        let pipe = loop {
            retry_count += 1;
            if retry_count == 1 {
                trace!("Trying to open pipe: {}", pipe_name.to_string_lossy());
            } else if retry_count % 20 == 0 {
                // Log every 20th attempt to avoid spam
                info!(
                    "Still waiting for pipe '{}' (attempt {})",
                    pipe_name.to_string_lossy(),
                    retry_count
                );
            } else {
                trace!(
                    "Trying to open pipe: {} (attempt {})",
                    pipe_name.to_string_lossy(),
                    retry_count
                );
            }
            // Open pipe with read/write access if bidirectional mode is enabled
            let access_mode = if args.bidirectional {
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
            } else {
                FILE_GENERIC_READ.0
            };

            let h = CreateFileA(
                PCSTR(pipe_name.as_ptr() as *const u8),
                access_mode,
                FILE_SHARE_NONE,
                Some(null_mut()),
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            );

            match h {
                Ok(handle) if handle != INVALID_HANDLE_VALUE => {
                    info!("Successfully connected to named pipe");
                    break handle;
                }
                _ => {
                    debug!(
                        "Pipe not available, retrying in {}ms...",
                        args.retry_interval
                    );
                    std::thread::sleep(std::time::Duration::from_millis(args.retry_interval));
                    if !running.load(Ordering::SeqCst) {
                        info!("Shutdown signal received while waiting for pipe");
                        return;
                    }
                }
            }
        };

        // Create UDP socket
        let (udp_sock, udp_addr) = match create_udp_socket(&args.udp_ip, args.udp_port) {
            Ok((sock, addr)) => {
                info!("Created UDP socket for {}:{}", args.udp_ip, args.udp_port);
                (sock, addr)
            }
            Err(e) => {
                error!("Failed to create UDP socket: {}", e);
                return;
            }
        };

        info!("Starting UDP data forwarding...");

        let total_bytes_forwarded = if args.bidirectional {
            info!("Running in bidirectional UDP mode");
            run_bidirectional_udp_forwarding(pipe, udp_sock, &udp_addr, running, args)
        } else {
            info!("Running in unidirectional UDP mode (pipe -> UDP)");
            run_unidirectional_udp_forwarding(pipe, udp_sock, &udp_addr, running, args)
        };

        info!(
            "UDP session ended. Total bytes forwarded: {}",
            total_bytes_forwarded
        );

        // Cleanup
        closesocket(udp_sock);
        WSACleanup();

        info!("UDP mode cleanup complete");
    }
}

pub fn run_bidirectional_udp_forwarding(
    pipe: windows::Win32::Foundation::HANDLE,
    udp_sock: windows::Win32::Networking::WinSock::SOCKET,
    udp_addr: &SOCKADDR_IN,
    running: Arc<AtomicBool>,
    args: &Args,
) -> u64 {
    unsafe {
        let mut pipe_buffer = vec![0u8; args.buffer_size];
        let mut udp_buffer = vec![0u8; args.buffer_size];
        let mut total_bytes_forwarded = 0u64;

        info!("Starting bidirectional UDP data forwarding...");

        while running.load(Ordering::SeqCst) {
            let mut data_transferred = false;

            // Check for data from pipe to UDP
            let mut bytes_available = 0u32;
            let peek_result = PeekNamedPipe(pipe, None, 0, None, Some(&mut bytes_available), None);

            if peek_result.is_ok() && bytes_available > 0 {
                let mut read = 0u32;
                let result = ReadFile(pipe, Some(&mut pipe_buffer), Some(&mut read), None);

                if let Ok(()) = result {
                    if read > 0 {
                        trace!("Read {} bytes from named pipe", read);

                        // Send UDP packet
                        let bytes_sent = sendto(
                            udp_sock,
                            &pipe_buffer[..read as usize],
                            0,
                            udp_addr as *const SOCKADDR_IN as *const _,
                            std::mem::size_of::<SOCKADDR_IN>() as i32,
                        );

                        if bytes_sent == SOCKET_ERROR {
                            let error = WSAGetLastError();
                            if error.0 == 10035 {
                                // WSAEWOULDBLOCK
                                std::thread::sleep(std::time::Duration::from_micros(10));
                                continue;
                            } else {
                                debug!("UDP send failed with error {}", error.0);
                                return total_bytes_forwarded;
                            }
                        } else {
                            total_bytes_forwarded += read as u64;
                            trace!("Forwarded {} bytes: pipe -> UDP", read);
                            data_transferred = true;
                        }
                    }
                }
            }

            // Check for data from UDP to pipe
            let bytes_received = recv(udp_sock, &mut udp_buffer, SEND_RECV_FLAGS(0));

            if bytes_received > 0 {
                trace!("Received {} bytes from UDP", bytes_received);

                // Write to pipe with partial write handling
                let mut bytes_to_write = bytes_received as usize;
                let mut offset = 0;

                while bytes_to_write > 0 {
                    let mut written = 0u32;
                    let result = WriteFile(
                        pipe,
                        Some(&udp_buffer[offset..offset + bytes_to_write]),
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
                trace!("Forwarded {} bytes: UDP -> pipe", bytes_received);
                data_transferred = true;
            } else if bytes_received == SOCKET_ERROR {
                let error = WSAGetLastError();
                if error.0 != 10035 {
                    // Not WSAEWOULDBLOCK, real error
                    debug!("UDP recv failed with error {}", error.0);
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

pub fn run_unidirectional_udp_forwarding(
    pipe: windows::Win32::Foundation::HANDLE,
    udp_sock: windows::Win32::Networking::WinSock::SOCKET,
    udp_addr: &SOCKADDR_IN,
    running: Arc<AtomicBool>,
    args: &Args,
) -> u64 {
    unsafe {
        let mut buffer = vec![0u8; args.buffer_size];
        let mut total_bytes_forwarded = 0u64;

        info!("Starting unidirectional UDP data forwarding (pipe -> UDP)...");

        // Data forwarding loop - pipe to UDP
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

                    // Send UDP packet
                    let bytes_sent = sendto(
                        udp_sock,
                        &buffer[..read as usize],
                        0,
                        udp_addr as *const SOCKADDR_IN as *const _,
                        std::mem::size_of::<SOCKADDR_IN>() as i32,
                    );

                    if bytes_sent == SOCKET_ERROR {
                        let error = WSAGetLastError();
                        if error.0 == 10035 {
                            // WSAEWOULDBLOCK
                            // Socket would block, wait a bit and try again
                            std::thread::sleep(std::time::Duration::from_micros(10));
                            continue;
                        } else {
                            debug!("UDP send failed with error {}", error.0);
                            return total_bytes_forwarded;
                        }
                    } else {
                        total_bytes_forwarded += read as u64;
                        trace!(
                            "Sent {} bytes via UDP (total: {} bytes)",
                            read, total_bytes_forwarded
                        );
                    }
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

pub fn create_udp_socket(
    ip: &str,
    port: u16,
) -> Result<(windows::Win32::Networking::WinSock::SOCKET, SOCKADDR_IN), Box<dyn std::error::Error>>
{
    unsafe {
        // Initialize Winsock
        let mut wsadata: WSADATA = mem::zeroed();
        if WSAStartup(0x0202, &mut wsadata) != 0 {
            return Err("Failed to initialize Winsock".into());
        }

        let sock = socket(AF_INET.0 as i32, SOCK_DGRAM, 0)?;

        // Set socket to non-blocking mode
        set_socket_nonblocking(sock)?;

        // Parse IP address
        let ip_bytes: Result<[u8; 4], _> = ip
            .split('.')
            .map(|s| s.parse::<u8>())
            .collect::<Result<Vec<_>, _>>()?
            .try_into();
        let ip_bytes = ip_bytes.map_err(|_| "Invalid IP address format")?;
        let ip_addr = u32::from_be_bytes(ip_bytes);

        let addr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: port.to_be(),
            sin_addr: windows::Win32::Networking::WinSock::IN_ADDR {
                S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 { S_addr: ip_addr },
            },
            sin_zero: [0; 8],
        };

        Ok((sock, addr))
    }
}
