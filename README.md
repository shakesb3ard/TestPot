<<<<<<< HEAD
#Honeypot – Rust-Based File Monitoring Honeypot

A lightweight honeypot agent written in Rust that monitors a folder for suspicious activity and logs real-time file events with clean formatting and timestamping. Built for Windows systems, this project is the foundation for a broader, more robust honeypot platform. 
Ultimately, I'm building this to create a multifunctional honeypot tool for security researchers and to become more proficient at programming with the help of AI.

🔍 What It Does (for now)
This honeypot agent:

🆕 Detects file creation
✏️ Detects file modification
🗑️ Detects file deletion
🔄 Detects file renaming
👀 Detects file access
Each event is:

Timestamped in UTC
Printed with clear emoji indicators
Optionally hashed (SHA-256) for integrity/tracking
📁 Why C:\Projects\honeypot-test?
This project is intentionally placed in a neutral, non-personal path:

✅ Keeps your Windows username private
✅ Portable for demos, GitHub publishing, and safe testing
✅ Mimics a writable, non-system folder for malware lure potential
✅ Requires no admin privileges to operate
You can change the monitored path by modifying folder_to_watch in main.rs.

🛠️ Tech Stack
Rust
notify for real-time file watching
tokio for async handling
chrono for timestamping
sha2 for file hashing
🚀 Roadmap
This project is part of a larger vision for an enterprise-level honeypot framework:

Phase	Goal
✅ Phase 1	CLI-based file monitor
✅ Phase 2	Timestamped alerts + file hashing
🔜 Phase 3	VirusTotal + Threat Intel Enrichment
🔜 Phase 4–5	Agent-server communication + Web Dashboard
🔜 Phase 6+	Custom honeypot deployment from dashboard
🧪 How to Run
Clone this repo:
git clone https://github.com/YOUR_USERNAME/honeypot-test.git
cd honeypot-test
Build and run:

bash Copy Edit cargo run You’ll see file events printed in the terminal in real time.

📄 License This project is licensed under the MIT License. See the LICENSE file for more details.
=======

#Honeypot – Rust-Based File Monitoring Honeypot

A lightweight honeypot agent written in Rust that monitors a folder for suspicious activity and logs real-time file events with clean formatting and timestamping. Built for Windows systems, this project is the foundation for a broader, robust honeypot platform.

---

## 🔍 What It Does (for now)

This honeypot agent:
- 🆕 Detects file creation
- ✏️ Detects file modification
- 🗑️ Detects file deletion
- 🔄 Detects file renaming
- 👀 Detects file access

Each event is:
- Timestamped in **UTC**
- Printed with **clear emoji indicators**
- Optionally hashed (SHA-256) for integrity/tracking

---

## 📁 Why `C:\Projects\honeypot-test`?

This project is intentionally placed in a neutral, non-personal path:
- ✅ Keeps your Windows username private
- ✅ Portable for demos, GitHub publishing, and safe testing
- ✅ Mimics a writable, non-system folder for malware lure potential
- ✅ Requires no admin privileges to operate

You can change the monitored path by modifying `folder_to_watch` in `main.rs`.

---

## 🛠️ Tech Stack

- **Rust**
- [`notify`](https://docs.rs/notify/latest/notify/) for real-time file watching
- `tokio` for async handling
- `chrono` for timestamping
- `sha2` for file hashing

---

## 🚀 Roadmap

This project is part of a larger vision for an enterprise-level honeypot framework:

| Phase | Goal |
|-------|------|
| ✅ Phase 1 | CLI-based file monitor |
| ✅ Phase 2 | Timestamped alerts + file hashing |
| 🔜 Phase 3 | VirusTotal + Threat Intel Enrichment |
| 🔜 Phase 4–5 | Agent-server communication + Web Dashboard |
| 🔜 Phase 6+ | Custom honeypot deployment from dashboard |

---

## 🧪 How to Run

1. Clone this repo:
   ```bash
   git clone https://github.com/YOUR_USERNAME/honeypot-test.git
   cd honeypot-test
Build and run:

bash
Copy
Edit
cargo run
You’ll see file events printed in the terminal in real time.


📄 License
This project is licensed under the MIT License. See the LICENSE file for more details.
>>>>>>> 7068b31 (Moved README and LICENSE to repo root for GitHub visibility.)
