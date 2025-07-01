#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
from datetime import datetime
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

# Banner
def show_banner():
    print("="*60)
    print("         🔐 XAMPP Exposure & LFI Scanner 🔍")
    print("               Created by CN ☣️")
    print("="*60)

# Common XAMPP exposure paths
XAMPP_PATHS = [
    "/xampp/",
    "/phpmyadmin/",
    "/dashboard/",
    "/server-status",
    "/.git/",
    "/config.php",
    "/index.php.bak",
    "/backup.zip",
    "/htdocs/",
    "/uploads/"
]

# LFI test path
LFI_TEST_PATH = "/?page=../../../../../../windows/system.ini"

def check_xampp(target, log_lines):
    headers = {"User-Agent": "Mozilla/5.0"}
    log_lines.append(f"\n[+] Scanning {target}")
    print(f"\n[+] Scanning {target}")

    for path in XAMPP_PATHS:
        url = urljoin(target, path)
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                log_lines.append(f"[!] Found {path} -> {url}")
                print(f"[!] Found {path} -> {url}")
            elif response.status_code in [401, 403]:
                log_lines.append(f"[!] Forbidden {path} (might exist) -> {url}")
                print(f"[!] Forbidden {path} (might exist) -> {url}")
        except requests.RequestException:
            log_lines.append(f"[-] Could not connect to {url}")
            print(f"[-] Could not connect to {url}")

    # LFI Test
    try:
        lfi_url = urljoin(target, LFI_TEST_PATH)
        lfi_response = requests.get(lfi_url, headers=headers, timeout=5)
        if "drivers" in lfi_response.text.lower() and "midi" in lfi_response.text.lower():
            log_lines.append(f"[!!] LFI Detected at: {lfi_url}")
            print(f"[!!] LFI Detected at: {lfi_url}")
        else:
            log_lines.append(f"[+] LFI test sent, no obvious signs at: {lfi_url}")
            print(f"[+] LFI test sent, no obvious signs at: {lfi_url}")
    except requests.RequestException:
        log_lines.append(f"[-] Could not connect to LFI URL: {lfi_url}")
        print(f"[-] Could not connect to LFI URL: {lfi_url}")

def main():
    show_banner()
    choice = input("🔍 Scan single target or multiple (file)? [single/file]: ").strip().lower()

    targets = []
    if choice == "single":
        target = input("🌐 Enter the target URL/IP (e.g., http://192.168.1.10): ").strip()
        if not target.startswith("http"):
            target = "http://" + target
        targets.append(target)

    elif choice == "file":
        input_path = prompt("📁 Enter path to target file: ", completer=PathCompleter())
        try:
            with open(input_path, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("❌ Target file not found!")
            return
    else:
        print("❌ Invalid option. Choose 'single' or 'file'.")
        return

    output_path = prompt("📝 Enter path to save output (e.g., results.txt): ", completer=PathCompleter())
    log_lines = []

    for target in targets:
        if not target.startswith("http"):
            target = "http://" + target
        check_xampp(target, log_lines)

    try:
        with open(output_path, 'w') as out_file:
            out_file.write("🔐 XAMPP Scanner Report - CN\n")
            out_file.write(f"🕒 Scanned on: {datetime.now()}\n")
            out_file.write("="*60 + "\n")
            out_file.write("\n".join(log_lines))
            out_file.write("\n" + "="*60 + "\n")
        print(f"\n✅ Results saved to: {output_path}")
    except Exception as e:
        print(f"❌ Error saving output: {e}")

if __name__ == "__main__":
    main()
