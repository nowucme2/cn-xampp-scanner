#!/usr/bin/env python3

import requests
from urllib.parse import urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import sys
import os
import json

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

def smart_url(input_target):
    if input_target.startswith("http"):
        return input_target
    https_url = f"https://{input_target}"
    http_url = f"http://{input_target}"
    try:
        response = requests.get(https_url, timeout=5, verify=False)
        return https_url
    except requests.exceptions.SSLError:
        print(f"[!] SSL error on {https_url}, falling back to HTTP.")
        return http_url
    except requests.exceptions.RequestException:
        return http_url

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
                    if "Index of /" in response.text:
                        entry["directory_listing"] = True
                    else:
                        entry["directory_listing"] = False
                    result["findings"].append(entry)
                    print(f"[!] Found {path} -> {url}")
                elif response.status_code in [401, 403]:
                    entry["access"] = "forbidden"
                    result["findings"].append(entry)
                    print(f"[!] Forbidden {path} (might exist) -> {url}")
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
        root_response = requests.get(target, headers=headers, timeout=5, verify=False)
        missing_headers = [h for h in SEC_HEADERS if h not in root_response.headers]
        if missing_headers:
            result["missing_security_headers"] = missing_headers
            print(f"[SEC] Missing headers at {target}: {', '.join(missing_headers)}")

        # Fingerprinting
        server = root_response.headers.get("Server", "Unknown")
        powered = root_response.headers.get("X-Powered-By", "Unknown")
        result["fingerprint"] = {"server": server, "x_powered_by": powered}

    except Exception as e:
        print(f"[ERROR] Unexpected error while scanning {target}: {e}")
    return result

def main():
    try:
        show_banner()

        if len(sys.argv) < 3:
            print("Usage: ./scanner.py <target_or_file> <output_file>")
            sys.exit(1)

        input_path = sys.argv[1]
        output_path = sys.argv[2]

        if os.path.isfile(input_path):
            with open(input_path, 'r') as f:
                raw_targets = [line.strip() for line in f if line.strip()]
        else:
            raw_targets = [input_path.strip()]

        targets = [smart_url(t) for t in raw_targets]

        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_target = {executor.submit(check_target, t): t for t in targets}
            for future in as_completed(future_to_target):
                results.append(future.result())

        # Write results
        with open(output_path, 'w') as out_file:
            out_file.write("\U0001f510 CN XAMPP Scanner Report\n")
            out_file.write(f"\U0001f552 Date: {datetime.now()}\n")
            out_file.write("="*60 + "\n")
            for r in results:
                out_file.write(json.dumps(r, indent=2) + "\n")
            out_file.write("="*60 + "\n")

        print(f"\n✅ Results saved to: {output_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
