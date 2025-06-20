// src/named_pipe.rs
use std::ffi::CString;
use std::ptr::null_mut;
use tracing::{debug, info};
use windows::{
    Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    Win32::Storage::FileSystem::{
        CreateFileA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    },
    Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    },
    core::PCSTR,
};

/// Enhanced pipe connection function with retry logic and proper configuration
/// This replaces the inline pipe connection logic in other modules
pub fn connect_to_pipe_with_retry(
    pipe_name: &std::ffi::CString,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    args: &crate::Args,
    use_overlapped: bool,
) -> Option<windows::Win32::Foundation::HANDLE> {
    use std::sync::atomic::Ordering;
    use tracing::{debug, info, trace};

    unsafe {
        let mut retry_count = 0u32;

        loop {
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

            // Determine access mode based on bidirectional setting
            let access_mode = if args.bidirectional {
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
            } else {
                FILE_GENERIC_READ.0
            };

            // Determine file flags based on usage context
            let file_flags = if use_overlapped {
                windows::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED
            } else {
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0)
            };

            let handle_result = CreateFileA(
                PCSTR(pipe_name.as_ptr() as *const u8),
                access_mode,
                windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
                Some(null_mut()),
                OPEN_EXISTING,
                file_flags,
                None,
            );

            match handle_result {
                Ok(handle) if handle != INVALID_HANDLE_VALUE => {
                    info!("Successfully connected to named pipe");
                    return Some(handle);
                }
                _ => {
                    debug!(
                        "Pipe not available, retrying in {}ms...",
                        args.retry_interval
                    );
                    std::thread::sleep(std::time::Duration::from_millis(args.retry_interval));
                    if !running.load(Ordering::SeqCst) {
                        info!("Shutdown signal received while waiting for pipe");
                        return None;
                    }
                }
            }
        }
    }
}

/// Creates a named pipe server and runs it, forwarding data to Unix socket or UDP
/// This function will block and run the pipe server
pub fn create_and_run_pipe_server(
    pipe_name: &str,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    args: &crate::Args,
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let pipe_name_cstring = CString::new(pipe_name)?;

        info!("Creating named pipe server: {}", pipe_name);

        loop {
            // Create a new pipe instance for each client
            let pipe_handle = CreateNamedPipeA(
                PCSTR(pipe_name_cstring.as_ptr() as *const u8),
                PIPE_ACCESS_DUPLEX, // Allow both read and write
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES, // Allow multiple instances
                4096,                     // Out buffer size
                4096,                     // In buffer size
                0,                        // Default timeout
                None,                     // Default security
            )?;

            if pipe_handle == INVALID_HANDLE_VALUE {
                return Err("Failed to create named pipe".into());
            }

            info!("Named pipe server created, waiting for client connections...");

            // Wait for a client to connect
            let connect_result = ConnectNamedPipe(pipe_handle, None);

            if connect_result.is_err() {
                let error = windows::Win32::Foundation::GetLastError();
                if error.0 == 535 {
                    // ERROR_PIPE_CONNECTED
                    debug!("Client was already connected");
                } else {
                    debug!("ConnectNamedPipe failed with error: {}", error.0);
                    let _ = CloseHandle(pipe_handle);
                    continue;
                }
            }

            info!("Client connected to named pipe!");

            // Now handle this client - forward data from pipe to socket/UDP
            if args.use_udp {
                handle_pipe_client_udp(pipe_handle, running.clone(), args);
            } else {
                handle_pipe_client_socket(pipe_handle, running.clone(), args);
            }

            // Client disconnected, close this pipe instance
            let _ = DisconnectNamedPipe(pipe_handle);
            let _ = CloseHandle(pipe_handle);

            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Shutdown signal received, stopping pipe server");
                break;
            }

            info!("Client disconnected, waiting for next connection...");
        }

        Ok(())
    }
}

fn handle_pipe_client_socket(
    pipe_handle: windows::Win32::Foundation::HANDLE,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    args: &crate::Args,
) {
    use crate::unix_socket::try_connect_to_existing_socket;

    let socket_path = args.socket_path.as_ref().unwrap();

    // Try to connect to existing socket
    let sock = match try_connect_to_existing_socket(socket_path) {
        Ok(sock) => {
            info!("Connected to existing Unix socket in client mode");
            sock
        }
        Err(_) => {
            info!(
                "No existing socket found, pipe server mode requires an existing socket listener"
            );
            return;
        }
    };

    // Forward data from pipe to socket
    if args.bidirectional {
        // Use the existing bidirectional forwarding function
        let total_bytes =
            crate::forward::bidi::run_bidirectional_forwarding(pipe_handle, sock, running, args);
        info!(
            "Pipe client session ended. Total bytes forwarded: {}",
            total_bytes
        );
    } else {
        // Use the existing unidirectional forwarding function
        let total_bytes =
            crate::forward::unidi::run_unidirectional_forwarding(pipe_handle, sock, running, args);
        info!(
            "Pipe client session ended. Total bytes forwarded: {}",
            total_bytes
        );
    }

    unsafe {
        windows::Win32::Networking::WinSock::closesocket(sock);
    }
}

fn handle_pipe_client_udp(
    pipe_handle: windows::Win32::Foundation::HANDLE,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    args: &crate::Args,
) {
    // Create UDP socket and address
    let (udp_sock, udp_addr) = match crate::udp::create_udp_socket(&args.udp_ip, args.udp_port) {
        Ok((sock, addr)) => {
            info!("Created UDP socket for {}:{}", args.udp_ip, args.udp_port);
            (sock, addr)
        }
        Err(e) => {
            debug!("Failed to create UDP socket: {}", e);
            return;
        }
    };

    // Forward data from pipe to UDP
    if args.bidirectional {
        let total_bytes = crate::udp::run_bidirectional_udp_forwarding(
            pipe_handle,
            udp_sock,
            &udp_addr,
            running,
            args,
        );
        info!(
            "UDP pipe client session ended. Total bytes forwarded: {}",
            total_bytes
        );
    } else {
        let total_bytes = crate::udp::run_unidirectional_udp_forwarding(
            pipe_handle,
            udp_sock,
            &udp_addr,
            running,
            args,
        );
        info!(
            "UDP pipe client session ended. Total bytes forwarded: {}",
            total_bytes
        );
    }

    unsafe {
        windows::Win32::Networking::WinSock::closesocket(udp_sock);
    }
}
