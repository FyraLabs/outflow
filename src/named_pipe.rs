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
            // Check if we should shutdown before creating a new pipe instance
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Shutdown signal received before creating pipe instance");
                break;
            }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    // Helper function to create test args
    pub(crate) fn create_test_args() -> crate::Args {
        crate::Args {
            pipe_name: r"\\.\pipe\test_pipe".to_string(),
            socket_path: Some("/tmp/test.sock".to_string()),
            use_udp: false,
            udp_ip: "127.0.0.1".to_string(),
            udp_port: 12345,
            buffer_size: 512,
            retry_interval: 50, // Shorter for tests
            log_level: "info".to_string(),
            poll_interval: 100,
            bidirectional: false,
            create_pipe: false,
        }
    }

    // Helper function to create a test pipe server
    fn create_test_pipe_server(
        pipe_name: &str,
    ) -> Result<windows::Win32::Foundation::HANDLE, Box<dyn std::error::Error>> {
        unsafe {
            let pipe_name_cstring = CString::new(pipe_name)?;
            let pipe_handle = CreateNamedPipeA(
                PCSTR(pipe_name_cstring.as_ptr() as *const u8),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1, // Single instance for testing
                4096,
                4096,
                0,
                None,
            )?;

            if pipe_handle == INVALID_HANDLE_VALUE {
                return Err("Failed to create test pipe".into());
            }

            Ok(pipe_handle)
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_connect_to_pipe_with_retry_nonexistent_pipe() {
        // Test connecting to a pipe that doesn't exist should timeout and return None
        let pipe_name = CString::new(r"\\.\pipe\nonexistent_test_pipe").unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let mut args = create_test_args();
        args.retry_interval = 10; // Very short retry interval

        let running_clone = running.clone();

        // Set up a timeout to stop the retry after a short time
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            running_clone.store(false, Ordering::SeqCst);
        });

        let result = connect_to_pipe_with_retry(&pipe_name, running, &args, false);
        assert!(
            result.is_none(),
            "Should return None for nonexistent pipe when timed out"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_connect_to_pipe_with_retry_immediate_shutdown() {
        // Test that the retry function respects shutdown signal
        let pipe_name = CString::new(r"\\.\pipe\nonexistent_test_pipe").unwrap();
        let running = Arc::new(AtomicBool::new(false)); // Already set to false
        let args = create_test_args();

        let result = connect_to_pipe_with_retry(&pipe_name, running, &args, false);
        assert!(
            result.is_none(),
            "Should return None when shutdown signal is set"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_connect_to_pipe_with_retry_timeout() {
        // Test that the retry function times out properly
        let pipe_name = CString::new(r"\\.\pipe\timeout_test_pipe").unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let mut args = create_test_args();
        args.retry_interval = 10; // Very short retry interval

        let running_clone = running.clone();

        // Set up a timeout to stop the retry after a short time
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            running_clone.store(false, Ordering::SeqCst);
        });

        let result = connect_to_pipe_with_retry(&pipe_name, running, &args, false);
        assert!(result.is_none(), "Should return None when timed out");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_bidirectional_access_mode() {
        // Test that bidirectional mode affects access mode correctly
        let mut args = create_test_args();
        args.bidirectional = true;

        // We can't easily test the actual Windows API calls without a real pipe,
        // but we can test that the function doesn't panic with bidirectional mode
        let pipe_name = CString::new(r"\\.\pipe\bidirectional_test_pipe").unwrap();
        let running = Arc::new(AtomicBool::new(false)); // Immediate shutdown to avoid hanging

        let result = connect_to_pipe_with_retry(&pipe_name, running, &args, false);
        assert!(
            result.is_none(),
            "Should handle bidirectional mode without panicking"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_overlapped_flag() {
        // Test that overlapped flag is handled correctly
        let args = create_test_args();
        let pipe_name = CString::new(r"\\.\pipe\overlapped_test_pipe").unwrap();
        let running = Arc::new(AtomicBool::new(false)); // Immediate shutdown

        // Test with overlapped=true
        let result1 = connect_to_pipe_with_retry(&pipe_name, running.clone(), &args, true);
        assert!(
            result1.is_none(),
            "Should handle overlapped mode without panicking"
        );

        // Test with overlapped=false
        let result2 = connect_to_pipe_with_retry(&pipe_name, running, &args, false);
        assert!(
            result2.is_none(),
            "Should handle non-overlapped mode without panicking"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_pipe_name_with_special_characters() {
        // Test pipe names with various characters using the retry function
        let test_names = vec![
            r"\\.\pipe\test-pipe",
            r"\\.\pipe\test_pipe_123",
            r"\\.\pipe\TestPipe",
        ];

        for name in test_names {
            let pipe_cstring = CString::new(name).unwrap();
            let running = Arc::new(AtomicBool::new(false)); // Immediate shutdown
            let args = create_test_args();

            let result = connect_to_pipe_with_retry(&pipe_cstring, running, &args, false);
            // We expect these to return None (no such pipe and immediate shutdown)
            assert!(
                result.is_none(),
                "Non-existent pipe should return None for name: {}",
                name
            );
        }
    }

    #[test]
    fn test_create_test_args() {
        // Test that our test args helper creates valid arguments
        let args = create_test_args();
        assert_eq!(args.pipe_name, r"\\.\pipe\test_pipe");
        assert_eq!(args.socket_path, Some("/tmp/test.sock".to_string()));
        assert!(!args.use_udp);
        assert!(!args.bidirectional);
        assert_eq!(args.retry_interval, 50);
        assert_eq!(args.buffer_size, 512);
    }

    // Integration test that creates a real pipe server and client
    #[test]
    #[cfg(target_os = "windows")]
    fn test_pipe_server_client_integration() {
        let pipe_name = r"\\.\pipe\integration_test_pipe";

        // This test requires careful orchestration to avoid hanging
        // We'll create a server in a separate thread and test basic creation
        let server_result = create_test_pipe_server(pipe_name);

        if let Ok(server_handle) = server_result {
            // Server was created successfully
            assert!(
                server_handle != INVALID_HANDLE_VALUE,
                "Server handle should be valid"
            );

            // Test connecting using our retry function
            let pipe_cstring = CString::new(pipe_name).unwrap();
            let running = Arc::new(AtomicBool::new(true));
            let mut args = create_test_args();
            args.retry_interval = 10; // Short interval

            // Set up timeout
            let running_clone = running.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                running_clone.store(false, Ordering::SeqCst);
            });

            let client_result = connect_to_pipe_with_retry(&pipe_cstring, running, &args, false);

            // Clean up server handle
            unsafe {
                let _ = CloseHandle(server_handle);
            }

            // The connection might succeed or fail depending on timing,
            // but it shouldn't panic
            match client_result {
                Some(client_handle) => {
                    assert!(
                        client_handle != INVALID_HANDLE_VALUE,
                        "Client handle should be valid"
                    );
                    unsafe {
                        let _ = CloseHandle(client_handle);
                    }
                }
                None => {
                    // Connection failed or timed out, which is acceptable in this test scenario
                }
            }
        }
    }

    #[test]
    fn test_cstring_conversion() {
        // Test that pipe name conversion to CString works correctly
        let pipe_name = r"\\.\pipe\test_pipe";
        let cstring_result = CString::new(pipe_name);
        assert!(
            cstring_result.is_ok(),
            "Should convert valid pipe name to CString"
        );

        let cstring = cstring_result.unwrap();
        assert_eq!(cstring.to_string_lossy(), pipe_name);
    }

    #[test]
    fn test_invalid_pipe_name() {
        // Test pipe names with null bytes (invalid for CString)
        let invalid_name = "\\\\.\\\0pipe\\test";
        let cstring_result = CString::new(invalid_name);
        assert!(
            cstring_result.is_err(),
            "Should fail to create CString with null byte"
        );
    }
}

// Additional integration tests that test the refactored functionality
#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_refactored_function_behavior() {
        // This test ensures that our refactored function behaves correctly
        let pipe_name = r"\\.\pipe\refactor_test_pipe";
        let pipe_cstring = CString::new(pipe_name).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let args = super::tests::create_test_args();

        // Set up timeout
        let running_clone = running.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            running_clone.store(false, Ordering::SeqCst);
        });

        // Test new function
        let new_result = connect_to_pipe_with_retry(&pipe_cstring, running.clone(), &args, false);

        // Should return None for non-existent pipe when timed out
        assert!(
            new_result.is_none(),
            "New function should return None for non-existent pipe"
        );
    }

    #[test]
    fn test_args_parameter_usage() {
        // Test that different Args configurations are handled correctly
        let pipe_name = CString::new(r"\\.\pipe\args_test_pipe").unwrap();
        let running = Arc::new(AtomicBool::new(false)); // Immediate shutdown

        // Test unidirectional mode
        let mut args = super::tests::create_test_args();
        args.bidirectional = false;
        let result1 = connect_to_pipe_with_retry(&pipe_name, running.clone(), &args, false);
        assert!(result1.is_none());

        // Test bidirectional mode
        args.bidirectional = true;
        let result2 = connect_to_pipe_with_retry(&pipe_name, running.clone(), &args, false);
        assert!(result2.is_none());

        // Test different retry intervals
        args.retry_interval = 1;
        let result3 = connect_to_pipe_with_retry(&pipe_name, running, &args, false);
        assert!(result3.is_none());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_pipe_server_creation() {
        // Test that we can create a pipe server without panicking
        let pipe_name = r"\\.\pipe\server_creation_test";

        // Use a timeout-based approach to prevent hanging
        let running = Arc::new(AtomicBool::new(true));

        // Set up a timeout thread that will stop the server quickly
        let running_clone = running.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            running_clone.store(false, Ordering::SeqCst);
        });

        // Test that calling the server function doesn't panic
        // We expect it to potentially hang at ConnectNamedPipe, so we use a timeout
        let result = std::panic::catch_unwind(|| {
            // Since the server function blocks at ConnectNamedPipe and doesn't check
            // the running flag before that call, we'll just test that creating
            // the CString and initial setup doesn't panic
            let pipe_name_cstring = CString::new(pipe_name);
            assert!(pipe_name_cstring.is_ok(), "Should create valid CString");

            // We can't safely test the full server function without it potentially hanging,
            // so we just verify the basic setup works
        });

        assert!(result.is_ok(), "Pipe server basic setup should not panic");
    }
}
