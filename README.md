
# Rust-Based File Monitoring Honeypot

A lightweight honeypot agent written in Rust that monitors a folder for any type of changes to files, logs real-time file events with clean formatting and timestamping, and allows users to check if a file is malicious with VirusTotal. Built for Windows systems, this project is the foundation for a broader, more robust honeypot platform. 
Ultimately, with the help of AI, I'm building this to create a multifunctional honeypot tool for security researchers and to become more proficient at programming.

---

## 🔍 What It Does (for now)

This honeypot agent:
- 🆕 Detects file creation
- ✏️ Detects file modification
- 🗑️ Detects file deletion
- 🔄 Detects file renaming
- 👀 Detects file access
- Sends a post request to VT to check file hashes
- Gives the user an option to upload a file

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



## 🚀 Roadmap

This project is part of a larger vision for an enterprise-level honeypot framework:

| Phase | Goal |
|-------|------|
| ✅ Phase 1 | CLI-based file monitor |
| ✅ Phase 2 | Timestamped alerts + file hashing |
| ✅ Phase 3 | VirusTotal + Threat Intel Enrichment |
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
