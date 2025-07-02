#!/usr/bin/env python3

import requests
from urllib.parse import urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import sys
import os
import json
import socket
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Banner
def show_banner():
    print("="*60)
    print("         🔐 CN XAMPP Exposure & LFI Scanner 🔍")
    print("               Created by CN ☣️")
    print("="*60)

# Common exposure paths
XAMPP_PATHS = [
    "/xampp/", "/phpmyadmin/", "/dashboard/", "/server-status",
    "/.git/", "/config.php", "/index.php.bak", "/backup.zip", "/htdocs/",
    "/uploads/", "/.env", "/.git/config", "/phpinfo.php", "/.DS_Store",
    "/composer.lock", "/admin/", "/login/", "/administrator/"
]

# LFI test path
LFI_TEST_PATH = "/?page=../../../../../../windows/system.ini"

# Security headers to check
SEC_HEADERS = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]

# Common ports where XAMPP may be hosted
COMMON_PORTS = [80, 443, 8010, 8080, 8888]

def port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=3):
            print(f"[PORT OPEN] {ip}:{port}")
            return True
    except:
        print(f"[PORT CLOSED] {ip}:{port}")
        return False

def detect_http(ip):
    open_ports = [p for p in COMMON_PORTS if port_open(ip, p)]
    urls = []
    for port in open_ports:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{ip}:{port}"
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code:
                    urls.append(url)
                    break
            except:
                continue
    return urls

def check_target(target):
    headers = {"User-Agent": "Mozilla/5.0"}
    result = {"target": target, "findings": []}
    print(f"\n[+] Scanning {target}")
    try:
        for path in XAMPP_PATHS:
            url = urljoin(target, path)
            try:
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                entry = {"url": url, "status": response.status_code}
                if response.status_code == 200:
                    entry["directory_listing"] = "Index of /" in response.text
                    result["findings"].append(entry)
                    print(f"[!] Found {path} -> {url}")
                elif response.status_code in [401, 403]:
                    entry["access"] = "forbidden"
                    result["findings"].append(entry)
                    print(f"[!] Forbidden {path} (might exist) -> {url}")
                else:
                    print(f"[-] {url} - Status {response.status_code}")
            except requests.RequestException:
                print(f"[-] Could not connect to {url}")

        # LFI Test
        lfi_url = urljoin(target, LFI_TEST_PATH)
        try:
            lfi_response = requests.get(lfi_url, headers=headers, timeout=5, verify=False)
            if "drivers" in lfi_response.text.lower() and "midi" in lfi_response.text.lower():
                result["lfi"] = True
                print(f"[!!] LFI Detected at: {lfi_url}")
            else:
                result["lfi"] = False
                print(f"[+] LFI test sent, no obvious signs at: {lfi_url}")
        except requests.RequestException:
            print(f"[-] Could not connect to LFI URL: {lfi_url}")

        # Security headers check
        try:
            root_response = requests.get(target, headers=headers, timeout=5, verify=False)
            missing_headers = [h for h in SEC_HEADERS if h not in root_response.headers]
            if missing_headers:
                result["missing_security_headers"] = missing_headers
                print(f"[SEC] Missing headers at {target}: {', '.join(missing_headers)}")

            server = root_response.headers.get("Server", "Unknown")
            powered = root_response.headers.get("X-Powered-By", "Unknown")
            result["fingerprint"] = {"server": server, "x_powered_by": powered}
        except:
            print(f"[-] Couldn't retrieve headers for {target}")
    except Exception as e:
        print(f"[ERROR] Unexpected error while scanning {target}: {e}")
    return result

def export_csv(results, path):
    with open(path, 'w', newline='') as csvfile:
        fieldnames = ['Target', 'URL', 'Status', 'Directory Listing', 'LFI', 'Missing Headers', 'Server', 'X-Powered-By']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            target = r['target']
            lfi = r.get('lfi', False)
            missing = ','.join(r.get('missing_security_headers', []))
            server = r.get('fingerprint', {}).get('server', '')
            powered = r.get('fingerprint', {}).get('x_powered_by', '')
            if not r.get("findings"):
                writer.writerow({
                    'Target': target,
                    'URL': '',
                    'Status': '',
                    'Directory Listing': '',
                    'LFI': lfi,
                    'Missing Headers': missing,
                    'Server': server,
                    'X-Powered-By': powered
                })
            for f in r.get('findings', []):
                writer.writerow({
                    'Target': target,
                    'URL': f.get('url'),
                    'Status': f.get('status'),
                    'Directory Listing': f.get('directory_listing', False),
                    'LFI': lfi,
                    'Missing Headers': missing,
                    'Server': server,
                    'X-Powered-By': powered
                })

def main():
    try:
        show_banner()

        if len(sys.argv) < 3:
            print("Usage: ./scanner.py <target_or_file> <output_file_base>")
            sys.exit(1)

        input_path = sys.argv[1]
        output_base = sys.argv[2]
        json_path = output_base + ".json"
        csv_path = output_base + ".csv"

        if os.path.isfile(input_path):
            with open(input_path, 'r') as f:
                raw_targets = [line.strip() for line in f if line.strip()]
        else:
            raw_targets = [input_path.strip()]

        targets = []
        for t in raw_targets:
            ip = t.split(":")[0].replace("http://", "").replace("https://", "").strip("/")
            print(f"\n[*] Checking {ip} on common XAMPP ports...")
            urls = detect_http(ip)
            if not urls:
                print(f"[!] No accessible HTTP/S service found on {ip}")
                for port in COMMON_PORTS:
                    print(f"    ⛔ Tried {ip}:{port} (no service)")
            else:
                print(f"[+] Detected HTTP(S) services on {ip}:")
                for u in urls:
                    print(f"    🌐 {u}")
                targets.extend(urls)

        if not targets:
            print("\n[!] No targets to scan. Exiting.")
        else:
            results = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_target = {executor.submit(check_target, t): t for t in targets}
                for future in as_completed(future_to_target):
                    results.append(future.result())

            # Write to JSON
            with open(json_path, 'w') as out_file:
                out_file.write("🔐 CN XAMPP Scanner Report\n")
                out_file.write(f"🕒 Date: {datetime.now()}\n")
                out_file.write("="*60 + "\n")
                if not results:
                    out_file.write("No reachable services found.\n")
                else:
                    for r in results:
                        out_file.write(json.dumps(r, indent=2) + "\n")
                out_file.write("="*60 + "\n")

            # Write to CSV
            export_csv(results, csv_path)

            # Final Summary
            print("\n" + "="*60)
            print("📋 Summary of Findings:")
            for r in results:
                print(f"\n🖥️ Target: {r['target']}")
                for f in r.get("findings", []):
                    print(f"  [+] Found: {f['url']} - Status: {f['status']} {'[DIR LISTING]' if f.get('directory_listing') else ''}")
                if r.get("lfi"):
                    print("  [!!] LFI Detected")
                if r.get("missing_security_headers"):
                    print("  [SEC] Missing Headers:", ", ".join(r["missing_security_headers"]))
                fp = r.get("fingerprint", {})
                print(f"  [FP] Server: {fp.get('server', 'Unknown')} | X-Powered-By: {fp.get('x_powered_by', 'Unknown')}")

            print(f"\n✅ JSON Results saved to: {json_path}")
            print(f"✅ CSV Report saved to: {csv_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
