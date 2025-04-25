
// Import required items from crates
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, Result};
use notify::event::{ModifyKind, RenameMode}; //more fine-tuned event matching 
use std::path::PathBuf;
use tokio::sync::mpsc;
use chrono::Utc;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncReadExt;


//Calculates SHA-256 h ash for a file
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



#[tokio::main]
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
                    } else {
                        println!("Failed to hash file: {}", path.display());
                    }
                }
            }
        }
    }

    Ok(())
}



