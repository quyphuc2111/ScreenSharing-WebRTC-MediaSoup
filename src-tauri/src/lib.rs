use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::State;
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct ServerState {
    process: Mutex<Option<Child>>,
    info: Mutex<Option<ServerInfo>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    url: String,
    ip: String,
    port: u16,
}

fn get_local_ip() -> String {
    use std::net::UdpSocket;
    
    let socket = UdpSocket::bind("0.0.0.0:0").ok();
    if let Some(socket) = socket {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

#[tauri::command]
fn start_server(state: State<ServerState>) -> Result<ServerInfo, String> {
    let mut process_guard = state.process.lock().map_err(|e| e.to_string())?;
    
    // Check if already running
    if process_guard.is_some() {
        let info_guard = state.info.lock().map_err(|e| e.to_string())?;
        if let Some(info) = info_guard.as_ref() {
            return Ok(info.clone());
        }
    }

    // Get the sidecar path
    let sidecar_name = if cfg!(target_os = "windows") {
        "mediasoup-server.exe"
    } else {
        "mediasoup-server"
    };

    // Try to find the sidecar in different locations
    let possible_paths = vec![
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join(sidecar_name))),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("binaries").join(sidecar_name))),
        Some(std::path::PathBuf::from(format!("./binaries/{}", sidecar_name))),
    ];

    let mut sidecar_path = None;
    for path in possible_paths.into_iter().flatten() {
        if path.exists() {
            sidecar_path = Some(path);
            break;
        }
    }

    // For development, use npm/node directly
    let child = if let Some(path) = sidecar_path {
        Command::new(path)
            .spawn()
            .map_err(|e| format!("Failed to start sidecar: {}", e))?
    } else {
        // Development mode: run with npm
        #[cfg(target_os = "windows")]
        let npm = "npm.cmd";
        #[cfg(not(target_os = "windows"))]
        let npm = "npm";

        Command::new(npm)
            .args(["run", "start"])
            .current_dir("../mediasoup-server")
            .spawn()
            .map_err(|e| format!("Failed to start server (dev mode): {}", e))?
    };

    *process_guard = Some(child);

    // Wait a bit for server to start
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let ip = get_local_ip();
    let port = 3016u16;
    let info = ServerInfo {
        url: format!("ws://{}:{}", ip, port),
        ip,
        port,
    };

    let mut info_guard = state.info.lock().map_err(|e| e.to_string())?;
    *info_guard = Some(info.clone());

    Ok(info)
}

#[tauri::command]
fn stop_server(state: State<ServerState>) -> Result<(), String> {
    let mut process_guard = state.process.lock().map_err(|e| e.to_string())?;
    
    if let Some(mut child) = process_guard.take() {
        child.kill().map_err(|e| format!("Failed to stop server: {}", e))?;
    }

    let mut info_guard = state.info.lock().map_err(|e| e.to_string())?;
    *info_guard = None;

    Ok(())
}

#[tauri::command]
fn get_server_info(state: State<ServerState>) -> Result<ServerInfo, String> {
    let info_guard = state.info.lock().map_err(|e| e.to_string())?;
    info_guard.clone().ok_or_else(|| "Server not running".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ServerState::default())
        .invoke_handler(tauri::generate_handler![
            start_server,
            stop_server,
            get_server_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
