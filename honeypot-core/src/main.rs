
// Import required items from crates
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, Result};
use notify::event::{ModifyKind, RenameMode}; //more fine-tuned event matching 
use std::path::PathBuf;
use tokio::sync::mpsc;
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<()> {

    // Define the folder you want to monitor
    let mut folder_to_watch =  PathBuf::from("C:\\Users\\Public");
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
    for path in event.paths {
        println!(
            "[{}] {} => {}",
            timestamp,
            action,
            path.display()
        );
    }

}
    

    Ok(())

   
}

