use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use notify::event::{ModifyKind, RenameMode};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use serde_json::Value;
use std::env;
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::mpsc;

// Entry point for the honeypot program
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Load .env variables (VT_API_KEY and optionally HONEYPOT_PATH)
    dotenvy::dotenv().ok();

    // Get the folder to monitor from the environment or use a default path
    let folder_to_watch = PathBuf::from(
        env::var("HONEYPOT_PATH").unwrap_or_else(|_| "C:\\Projects\\honeypot-test".to_string())
    );

    // Set up a channel to receive file system events asynchronously
    let (tx, mut rx) = mpsc::channel(100);
    let handle = tokio::runtime::Handle::current();

    // Start file system watcher and set up the event handler
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
    println!("\n🔍 Monitoring folder: {}\n", folder_to_watch.display());

    // Event loop to handle file system events as they occur
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
            println!("[{}] {} => {}", timestamp, action, path.display());
        }

        // Only handle files that are created or modified
        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            for path in &event.paths {
                if path.is_file() {
                    // Hash the file contents using SHA256
                    if let Some(hash) = hash_file(path).await {
                        println!("File hash: {}", hash);

                        // Check if this file is known to VirusTotal already
                        if let Some(vt_response) = check_VT_hash(&hash).await {
                            // If it is, print the verdicts from available AV engines
                            if let Some(map) = vt_response.as_object() {
                                for (engine, result) in map.iter() {
                                    let category = result.get("category").and_then(|c| c.as_str()).unwrap_or("unknown");
                                    let result_label = result.get("result").and_then(|r| r.as_str()).unwrap_or("none");
                                    println!("🔍 Engine: {:<20} | Category: {:<12} | Label: {}", engine, category, result_label);
                                }
                            }
                        } else {
                            // Prompt user to upload unknown file to VirusTotal
                            println!("Unknown file. Upload to VirusTotal? (Y/N): ");
                            let mut input = String::new();
                            std::io::stdin().read_line(&mut input)?;
                            if input.trim().eq_ignore_ascii_case("y") {
                                // Upload and print scan results with progress
                                match upload_file_to_virustotal(path).await {
                                    Ok(true) => println!("✅ Upload and analysis complete."),
                                    Ok(false) => println!("⚠️ Upload succeeded but analysis incomplete."),
                                    Err(e) => eprintln!("❌ Upload error: {}", e),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// Reads and hashes a file using SHA256
async fn hash_file(path: &Path) -> Option<String> {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut file = File::open(path).await.ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![];
    file.read_to_end(&mut buffer).await.ok()?;
    hasher.update(&buffer);
    Some(format!("{:x}", hasher.finalize()))
}

// Checks VirusTotal for known analysis of a file hash
async fn check_VT_hash(hash: &str) -> Option<Value> {
    let api_key = std::env::var("VT_API_KEY").ok()?;
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    let client = reqwest::Client::new();
    let response = client.get(&url)
        .header("x-apikey", api_key)
        .send().await.ok()?;

    if response.status().is_success() {
        let json: Value = response.json().await.ok()?;
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
}

// Uploads a file to VirusTotal and polls for results
async fn upload_file_to_virustotal(path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>> {
    use reqwest::multipart;
    use reqwest::Body;
    use tokio::fs::File;
    use tokio_util::io::ReaderStream;

    let api_key = std::env::var("VT_API_KEY")?;
    let client = reqwest::Client::new();

    // Open file and stream it for multipart upload
    let file = File::open(path).await?;
    let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
    let stream = ReaderStream::new(file);
    let body = Body::wrap_stream(stream);
    let part = multipart::Part::stream(body).file_name(file_name.clone());
    let form = multipart::Form::new().part("file", part);

    // Submit file to VirusTotal for scanning
    let upload_response = client
        .post("https://www.virustotal.com/api/v3/files")
        .header("x-apikey", &api_key)
        .multipart(form)
        .send()
        .await?;

    if !upload_response.status().is_success() {
        println!("Upload failed with status: {}", upload_response.status());
        return Ok(false);
    }

    // Parse the returned analysis ID
    let response_json: Value = upload_response.json().await?;
    let analysis_id = response_json["data"]["id"].as_str().unwrap();
    println!("✅ File uploaded. Analysis ID: {}", analysis_id);

    // Poll VirusTotal every 5 seconds for up to 30 seconds total
    println!("⏳ Polling VirusTotal for analysis status...");
    let pb = ProgressBar::new(6);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/blue} {pos:>2}/6 polls")
            .unwrap()
            .progress_chars("##-")
    );

    let analysis_url = format!("https://www.virustotal.com/api/v3/analyses/{}", analysis_id);
    let mut analysis_status = String::new();

    for _ in 0..6 {
        pb.inc(1);
        let analysis_response = client
            .get(&analysis_url)
            .header("x-apikey", &api_key)
            .send()
            .await?;

        let analysis_json: Value = analysis_response.json().await?;
        analysis_status = analysis_json["data"]["attributes"]["status"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        if analysis_status == "completed" {
            pb.finish_with_message("🔍 Analysis complete.");
            if let Some(stats) = analysis_json["data"]["attributes"]["stats"].as_object() {
                println!("\n📊 VirusTotal Scan Summary:");
                for (category, count) in stats {
                    println!("{:>15}: {}", category, count);
                }
            } else {
                println!("⚠️ No scan stats found.");
            }
            return Ok(true);
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    pb.finish_with_message("⚠️ Timed out waiting for results.");
    println!("Status after timeout: {}", analysis_status);
    Ok(false)
}
