
// Standard Library
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

// Async + Tokio
use tokio::sync::mpsc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_util::codec::{FramedRead, BytesCodec};

// Time & Crypto
use chrono::Utc;
use sha2::{Digest, Sha256};

// External Crates
use dotenvy::dotenv;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, Result};
use notify::event::{ModifyKind, RenameMode};
use reqwest::multipart;


//Calculates SHA-256 hash for a file

async fn hash_file(path: &PathBuf) -> Option<String> {
    let mut file = File::open(path).await.ok()?;
    let mut hasher = Sha256::new(); 
    let mut buffer = [0u8; 1024];

    loop {
        let n = file.read(&mut buffer).await.ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);    
    }

    Some(format!("{:x}", hasher.finalize()))
}

// Loads the VirusTotal API key from the `.env` file using the dotenvy crate.
// This keeps the API key out of the source code and helps avoid accidental leaks.
// Panics with a clear message if the key is not set.

fn get_virustotal_key() -> String {
    dotenv().ok(); // Load environment variables from .env file
    env::var("VT_API_KEY").expect("VT_API_KEY must be set in .env")
}

// Queries the VirusTotal API to check if a file hash is malicious.
// Returns JSON response if found.

async fn check_VT_hash(hash: &str) -> Option<serde_json::Value> {
    let api_key = get_virustotal_key();
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .ok()?;

    if response.status().is_success() {
    let json = response.json::<serde_json::Value>().await.ok()?;
    if let Some(results) = json.get("data")
                               .and_then(|d| d.get("attributes"))
                               .and_then(|a| a.get("last_analysis_results")) {
        return Some(results.clone());
    }
    Some(json)
} else {
    println!("Error: {}", response.status());
    None
}

// Uploads a file to VirusTotal if it's not already known.

async fn upload_file_to_virustotal(path: &PathBuf) -> bool {
    let api_key = get_virustotal_key();
    let url = "https://www.virustotal.com/api/v3/files";

    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => {
            println!("❌ Failed to open file for upload: {}", path.display());
            return false;
        }
    };

    let stream = tokio_util::codec::FramedRead::new(file, tokio_util::codec::BytesCodec::new());
    let body = reqwest::Body::wrap_stream(stream);

    let part = reqwest::multipart::Part::stream(body)
        .file_name(path.file_name().unwrap().to_string_lossy())
        .mime_str("application/octet-stream")
        .unwrap();

    let form = reqwest::multipart::Form::new().part("file", part);

    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .header("x-apikey", api_key)
        .multipart(form)
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            println!("📤 Uploaded file to VirusTotal: {}", path.display());
            true
        }
        Ok(res) => {
            println!("⚠️ VirusTotal upload failed: HTTP {}", res.status());
            false
        }
        Err(err) => {
            println!("❌ VirusTotal upload error: {}", err);
            false
        }
    }
}


#[tokio::main]
// Main function to run the file system watcher

async fn main() -> Result<()> {

    // Define the folder you want to monitor
    let mut folder_to_watch =  PathBuf::from("C:\\Projects\\honeypot-test");
    println!("🔍 Monitoring folder: {:?}", folder_to_watch);

    // Create a Tokio channel for asynchronous event handling
    let (tx, mut rx) = mpsc::channel(100);

    // Get the handle to the current Tokio runtime
    // This is necessary to spawn tasks within the watcher callback
    // Create a watcher with a callback that sends events to the channel

    let handle = tokio::runtime::Handle::current();

    // Initialize file system watcher and set up the event handler

    let mut watcher = RecommendedWatcher::new(
    move |res| {
        let tx = tx.clone();
        // Use runtime handle to properly spawn async block inside a non-async closure
        handle.spawn(async move {
            if let Ok(event) = res {
                let _ = tx.send(event).await;
            }
        });
    },
    Config::default(),
)?;

// Begin watching the defined folder recursively (including subfolders)
// This will trigger events for any changes in the folder or its subfolders

    watcher.watch(&folder_to_watch, RecursiveMode::Recursive)?;

    while let Some(event) = rx.recv().await {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let action = match event.kind {
            EventKind::Create(_) => "🆕 CREATED",
            EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => "🔄 RENAMED",
            EventKind::Modify(_) => "✏️ MODIFIED",
            EventKind::Remove(_) => "🗑️ DELETED",
            EventKind::Access(_) => "👀 ACCESSED",
            _ => "❓ UNKNOWN",
        };
        
        // Print all paths associated with the event
        for path in &event.paths {
            println!(
                "[{}] {} => {}",
                timestamp,
                action,
                path.display()
            );
        }
    
        // file contents are hashed if the file was created or modified
        
        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            for path in &event.paths {
                if path.is_file() { 
                    if let Some(hash) = hash_file(path).await {
                        println!("File hash: {}", hash);

                        // Check if the file is already known to VirusTotal
                        
                        if let Some(vt_response) = check_VT_hash(&hash).await {
                            if let Some(map) = vt_response.as_object() {
                                for (engine, result) in map.iter() {
                                    let category = result.get("category").and_then(|c| c.as_str()).unwrap_or("unknown");
                                    println!("🔍 Engine: {:<20} | Verdict: {}", engine, category);
                                }
                            }
                        } else {
                            // User is prompted to upload the file to VirusTotal if it is not known

                            println!("❔ No VT hash found. Upload this file to VirusTotal for scanning? (y/n): ");
                            io::stdout().flush().unwrap();

                            let mut input = String::new();
                            if io::stdin().read_line(&mut input).is_ok() {
                                if input.trim() == "y" {
                                    upload_file_to_virustotal(path).await;
                                } else {
                                    println!("❌ Upload failed.");

                                } 
                            
                            }
                        }
                                            
                    } else {
                        println!("Failed to hash file: {}", path.display());

                        
                    }
                }
            }
        }
    }

    Ok(())
}



