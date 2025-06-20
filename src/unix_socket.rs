use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, trace, warn};
use windows::Win32::Networking::WinSock::{
    AF_UNIX, SOCK_STREAM, SOCKET_ERROR, WSACleanup, WSADATA, WSAGetLastError, WSAStartup, accept,
    bind, closesocket, connect, listen, socket,
};

use crate::forward::{run_bidirectional_forwarding, run_unidirectional_forwarding};
use crate::{Args, set_socket_nonblocking};

pub fn run_unix_socket_server(
    pipe_name: &CString,
    socket_path: &str,
    running: Arc<AtomicBool>,
    args: &Args,
) {
    // Clean up any stale socket file
    cleanup_socket_file(socket_path);

    unsafe {
        // Connect to Wine named pipe using the refactored function
        info!("Attempting to connect to named pipe...");
        info!(
            "Will retry indefinitely until pipe '{}' becomes available",
            pipe_name.to_string_lossy()
        );

        let pipe = match crate::named_pipe::connect_to_pipe_with_retry(
            pipe_name,
            running.clone(),
            args,
            true,
        ) {
            Some(handle) => handle,
            None => {
                info!("Pipe connection was cancelled due to shutdown signal");
                return;
            }
        };

        // Connect to host-side UNIX socket (accessible from Wine)
        info!("Initializing Winsock...");
        let mut wsadata: WSADATA = mem::zeroed();
        if WSAStartup(0x0202, &mut wsadata) != 0 {
            error!("Failed to initialize Winsock");
            panic!("Failed to initialize Winsock");
        }
        debug!("Winsock initialized successfully");

        info!("Creating Unix domain socket...");
        let sock = socket(AF_UNIX.into(), SOCK_STREAM, 0).expect("Failed to create socket");

        // Set socket to non-blocking mode for accept operations
        set_socket_nonblocking(sock).expect("Failed to set socket non-blocking");

        debug!("Socket created successfully");

        // For Unix socket, we need to create a sockaddr_un structure
        // In Wine, this should work with AF_UNIX
        let socket_path_cstring = CString::new(socket_path).unwrap();
        info!(
            "Setting up Unix socket at: {}",
            socket_path_cstring.to_string_lossy()
        );
        let mut addr: [u8; 110] = [0; 110]; // sockaddr_un size
        addr[0] = AF_UNIX as u8; // sa_family
        addr[1] = 0;
        // Copy the path starting at offset 2
        let path_bytes = socket_path_cstring.as_bytes();
        for (i, &byte) in path_bytes.iter().enumerate() {
            if i + 2 < addr.len() {
                addr[i + 2] = byte;
            }
        }
        trace!("Socket address structure prepared");

        // Bind the socket to the Unix domain socket path
        info!("Binding socket to path...");
        if bind(sock, addr.as_ptr() as *const _, addr.len() as i32) == SOCKET_ERROR {
            error!("Failed to bind to {}", socket_path);
            closesocket(sock);
            WSACleanup();
            panic!("Failed to bind to {}", socket_path);
        }
        debug!("Socket bound successfully");

        // Listen for incoming connections
        info!("Starting to listen for connections...");
        if listen(sock, 1) == SOCKET_ERROR {
            error!("Failed to listen on socket");
            closesocket(sock);
            WSACleanup();
            panic!("Failed to listen on socket");
        }

        info!("Listening for connections on {}...", socket_path);

        // Main server loop - keep accepting new clients
        while running.load(Ordering::SeqCst) {
            // Accept a client connection (non-blocking)
            let client_sock = match accept(sock, None, None) {
                Ok(sock) => {
                    info!("Client connected! Starting data forwarding...");
                    sock
                }
                Err(e) => {
                    // Check if it's just no pending connections (non-blocking)
                    let error = WSAGetLastError();
                    if error.0 == 10035 {
                        // WSAEWOULDBLOCK - no pending connections
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    } else {
                        error!("Failed to accept connection: {:?} (error {})", e, error.0);
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        continue;
                    }
                }
            };

            debug!("Starting data forwarding loop...");

            // Data forwarding loop for this client
            let total_bytes_forwarded = if args.bidirectional {
                info!("Running in bidirectional mode for this client");
                run_bidirectional_forwarding(pipe, client_sock, running.clone(), args)
            } else {
                info!("Running in unidirectional mode (pipe -> socket) for this client");
                run_unidirectional_forwarding(pipe, client_sock, running.clone(), args)
            };

            info!(
                "Client session ended. Total bytes forwarded: {}",
                total_bytes_forwarded
            );
            closesocket(client_sock);

            if running.load(Ordering::SeqCst) {
                info!("Client disconnected, waiting for next connection...");
            } else {
                info!("Shutdown signal received, stopping server...");
                break;
            }
        }

        // Cleanup
        info!("Cleaning up server resources...");
        closesocket(sock);
        WSACleanup();

        // Remove socket file
        cleanup_socket_file(socket_path);
        info!("Wine socket proxy shutdown complete");
    }
}

pub fn try_connect_to_existing_socket(
    socket_path: &str,
) -> Result<windows::Win32::Networking::WinSock::SOCKET, Box<dyn std::error::Error>> {
    unsafe {
        // Initialize Winsock
        let mut wsadata: WSADATA = mem::zeroed();
        if WSAStartup(0x0202, &mut wsadata) != 0 {
            return Err("Failed to initialize Winsock".into());
        }

        let sock = socket(AF_UNIX.into(), SOCK_STREAM, 0)?;

        // Set socket to non-blocking mode
        set_socket_nonblocking(sock)?;

        // Create sockaddr_un structure for connecting
        let socket_path_cstring = CString::new(socket_path)?;
        let mut addr: [u8; 110] = [0; 110];
        addr[0] = AF_UNIX as u8;
        addr[1] = 0;
        let path_bytes = socket_path_cstring.as_bytes();
        for (i, &byte) in path_bytes.iter().enumerate() {
            if i + 2 < addr.len() {
                addr[i + 2] = byte;
            }
        }

        if connect(sock, addr.as_ptr() as *const _, addr.len() as i32) == SOCKET_ERROR {
            closesocket(sock);
            WSACleanup();
            return Err("Failed to connect to existing socket".into());
        }

        Ok(sock)
    }
}

pub fn run_as_client(
    pipe_name: &CString,
    sock: windows::Win32::Networking::WinSock::SOCKET,
    running: Arc<AtomicBool>,
    args: &Args,
) {
    unsafe {
        // Connect to Wine named pipe using the refactored function
        info!("Attempting to connect to named pipe...");
        info!(
            "Will retry indefinitely until pipe '{}' becomes available",
            pipe_name.to_string_lossy()
        );

        let pipe = match crate::named_pipe::connect_to_pipe_with_retry(
            pipe_name,
            running.clone(),
            args,
            false,
        ) {
            Some(handle) => handle,
            None => {
                info!("Pipe connection was cancelled due to shutdown signal");
                closesocket(sock);
                WSACleanup();
                return;
            }
        };

        info!("Connected to existing socket, starting data forwarding...");

        let total_bytes_forwarded = if args.bidirectional {
            info!("Running in bidirectional mode");
            run_bidirectional_forwarding(pipe, sock, running, args)
        } else {
            info!("Running in unidirectional mode (pipe -> socket)");
            run_unidirectional_forwarding(pipe, sock, running, args)
        };

        info!(
            "Client session ended. Total bytes forwarded: {}",
            total_bytes_forwarded
        );

        // Cleanup
        closesocket(sock);
        WSACleanup();

        info!("Client mode cleanup complete");
    }
}

pub fn cleanup_socket_file(socket_path: &str) {
    if Path::new(socket_path).exists() {
        info!("Removing stale socket file: {}", socket_path);
        if let Err(e) = std::fs::remove_file(socket_path) {
            warn!("Failed to remove stale socket file: {}", e);
        } else {
            debug!("Successfully removed stale socket file");
        }
    }
}
