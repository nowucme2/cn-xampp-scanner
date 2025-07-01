# CN XAMPP Exposure & LFI Scanner 🔐

This tool scans for exposed XAMPP services and performs a basic Local File Inclusion (LFI) test.

## 📌 Features
- Detects exposed `/xampp/`, `/phpmyadmin/`, `.git`, backups, etc.
- Tests for basic Windows LFI vulnerability
- Works on single or bulk targets
- Saves results to an output file
- Tab-completion for file paths using `prompt_toolkit`

## ✅ Installation

```bash
pip3 install -r requirements.txt

🚀 Run the Tool

python3 scanner.py

📥 Example targets.txt

http://192.168.1.10
http://example.com
 



