// src/main.rs
mod forward;
mod named_pipe;
mod udp;
mod unix_socket;
use clap::Parser;
use std::ffi::CString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info};
use windows::Win32::Networking::WinSock::{FIONBIO, SOCKET_ERROR, ioctlsocket};

use crate::named_pipe::create_and_run_pipe_server;
use crate::udp::run_udp_mode;
use crate::unix_socket::{run_as_client, run_unix_socket_server, try_connect_to_existing_socket};

#[derive(Parser, Debug)]
#[command(name = "wine-socket-proxy")]
#[command(
    about = "A proxy that forwards data from Windows named pipes to Unix domain sockets or UDP"
)]
#[command(version)]
struct Args {
    /// Windows named pipe to read from
    #[arg(short = 'p', long = "pipe", env = "WINE_PROXY_PIPE")]
    pipe_name: String,

    /// Unix domain socket path
    #[arg(short = 's', long = "socket", env = "WINE_PROXY_SOCKET")]
    socket_path: Option<String>,

    /// Use UDP instead of Unix domain socket
    #[arg(
        long = "udp",
        env = "WINE_PROXY_UDP",
        action = clap::ArgAction::SetTrue
    )]
    use_udp: bool,

    /// UDP target IP address (only used with --udp)
    #[arg(
        long = "udp-ip",
        env = "WINE_PROXY_UDP_IP",
        default_value = "127.0.0.1"
    )]
    udp_ip: String,

    /// UDP target port (only used with --udp)
    #[arg(
        long = "udp-port",
        env = "WINE_PROXY_UDP_PORT",
        default_value = "12345"
    )]
    udp_port: u16,

    /// Buffer size for data transfers
    #[arg(
        short = 'b',
        long = "buffer-size",
        env = "WINE_PROXY_BUFFER_SIZE",
        default_value = "512"
    )]
    buffer_size: usize,

    /// Retry interval in milliseconds when pipe is not available
    #[arg(
        short = 'r',
        long = "retry-interval",
        env = "WINE_PROXY_RETRY_INTERVAL",
        default_value = "250"
    )]
    retry_interval: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(
        short = 'l',
        long = "log-level",
        env = "WINE_PROXY_LOG_LEVEL",
        default_value = "INFO"
    )]
    log_level: String,

    /// Poll interval in microseconds for checking data availability
    #[arg(
        long = "poll-interval",
        env = "WINE_PROXY_POLL_INTERVAL",
        default_value = "100"
    )]
    poll_interval: u64,

    /// Enable bidirectional communication (proxy data in both directions)
    #[arg(
        long = "bidirectional",
        env = "WINE_PROXY_BIDIRECTIONAL",
        action = clap::ArgAction::SetTrue
    )]
    bidirectional: bool,

    /// Create a named pipe if it doesn't exist (Windows only)
    #[arg(
        long = "create-pipe",
        env = "WINE_PROXY_CREATE_PIPE",
        action = clap::ArgAction::SetTrue
    )]
    create_pipe: bool,
}

fn set_socket_nonblocking(
    sock: windows::Win32::Networking::WinSock::SOCKET,
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let mut nonblocking = 1u32; // 1 = non-blocking, 0 = blocking
        if ioctlsocket(sock, FIONBIO, &mut nonblocking) == SOCKET_ERROR {
            return Err("Failed to set socket to non-blocking mode".into());
        }
        Ok(())
    }
}

fn main() {
    let args = Args::parse();

    // Validate arguments
    if !args.use_udp && args.socket_path.is_none() {
        eprintln!("Error: Either --socket must be provided or --udp must be specified");
        std::process::exit(1);
    }

    // Parse log level and initialize tracing
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => {
            eprintln!("Invalid log level: {}. Using INFO.", args.log_level);
            tracing::Level::INFO
        }
    };

    tracing_subscriber::fmt::fmt()
        .with_max_level(log_level)
        .init();

    let pipe_name = CString::new(args.pipe_name.clone()).unwrap();

    info!("Starting wine socket proxy");
    info!("Target pipe: {}", args.pipe_name);
    if args.use_udp {
        info!("UDP mode - Target: {}:{}", args.udp_ip, args.udp_port);
    } else if let Some(ref socket_path) = args.socket_path {
        info!("Unix socket mode - Socket path: {}", socket_path);
    }
    info!("Buffer size: {} bytes", args.buffer_size);
    info!("Retry interval: {}ms", args.retry_interval);
    info!("Poll interval: {}μs", args.poll_interval);
    info!("Log level: {}", args.log_level);
    info!("Bidirectional mode: {}", args.bidirectional);
    info!("Create pipe if missing: {}", args.create_pipe);

    // Set up signal handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        info!("Received interrupt signal, shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // Create named pipe server if requested
    if args.create_pipe {
        info!("Running in named pipe server mode");
        match create_and_run_pipe_server(&args.pipe_name, running, &args) {
            Ok(()) => {
                info!("Named pipe server ended normally");
            }
            Err(e) => {
                error!("Named pipe server failed: {}", e);
                std::process::exit(1);
            }
        }
        return; // Exit after pipe server mode
    }

    if args.use_udp {
        info!("Running in UDP mode");
        run_udp_mode(&pipe_name, running, &args);
    } else {
        let socket_path = args.socket_path.as_ref().unwrap(); // Safe because we validated above

        // Try to connect to existing socket first (client mode)
        info!("Checking for existing Unix socket at {}...", socket_path);
        if let Ok(existing_sock) = try_connect_to_existing_socket(socket_path) {
            info!("Found existing socket, running in CLIENT mode");
            run_as_client(&pipe_name, existing_sock, running, &args);
            return;
        }

        info!("No existing socket found, running in SERVER mode");
        run_unix_socket_server(&pipe_name, socket_path, running, &args);
    }
}
