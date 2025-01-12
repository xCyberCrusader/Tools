#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
    CTFR - Multiple Domains - Sheila A. Berta (UnaPibaGeek) - Enhanced
------------------------------------------------------------------------------
"""

## # LIBRARIES # ##
import re
import requests
import time
import os

## # CONTEXT VARIABLES # ##
version = 1.5  # Updated version

## # MAIN FUNCTIONS # ##

def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domains', type=str, nargs='+', required=True, help="Target domains (space-separated) or a file with domains.")
    parser.add_argument('-o', '--output', type=str, help="Output file.")
    return parser.parse_args()

def banner():
    global version
    b = r'''
          ____ _____ _____ ____  
         / ___|_   _|  ___|  _ \ 
        | |     | | | |_  | |_) |
        | |___  | | |  _| |  _ < 
         \____| |_| |_|   |_| \_\
    
     Version {v} - Multiple Domains Supported
    Enhanced for Robustness by NC-Security
    '''.format(v=version)
    print(b)

def clear_url(target):
    return re.sub(r'.*www\.', '', target, 1).split('/')[0].strip()

def save_subdomains(subdomain, output_file):
    with open(output_file, "a") as f:
        f.write(subdomain + '\n')

def get_subdomains(target, retries=3):
    subdomains = []
    url = f"https://crt.sh/?q=%.{target}&output=json"
    attempt = 0

    while attempt < retries:
        try:
            req = requests.get(url, timeout=10)
            req.raise_for_status()

            # Check if the response is not JSON
            if not req.headers.get("Content-Type", "").startswith("application/json"):
                print(f"[X] Unexpected response format for {target}.")
                print(f"Response content:\n{req.text}")  # Debug: Print response content
                return subdomains

            try:
                # Try parsing the JSON response
                for value in req.json():
                    subdomains.append(value['name_value'])
                return sorted(set(subdomains))
            except ValueError:
                print(f"[X] Failed to parse JSON response for {target}!")
                print(f"Response content:\n{req.text}")  # Debug: Print response content
                return subdomains

        except requests.RequestException as e:
            print(f"[X] Error fetching data for {target}: {e}")
            attempt += 1
            if attempt < retries:
                print(f"[!] Retrying {target}... ({attempt}/{retries})")
                time.sleep(2)
            else:
                print(f"[X] Giving up on {target} after {retries} retries.")
                return subdomains

    return subdomains

def process_domains(domains, output):
    for domain in domains:
        target = clear_url(domain)
        print(f"\n[!] ---- TARGET: {target} ---- [!]\n")

        subdomains = get_subdomains(target)

        if not subdomains:
            print("[X] No subdomains found!")
        else:
            for subdomain in subdomains:
                print(subdomain)
                if output is not None:
                    save_subdomains(subdomain, output)

        # Introduce a delay to prevent rate-limiting
        time.sleep(2)

    print("\n\n[!]  Done. Have a nice day! ;)")

def load_domains_from_file(file_path):
    """Load domains from a file and return a cleaned list."""
    if not os.path.exists(file_path):
        print(f"[X] File not found: {file_path}")
        exit(1)
    
    with open(file_path, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]  # Remove empty lines and spaces
    return domains

def main():
    banner()
    args = parse_args()

    # Check if input is a file
    input_domains = []
    if len(args.domains) == 1 and args.domains[0].endswith('.txt'):
        input_domains = load_domains_from_file(args.domains[0])
    else:
        input_domains = args.domains

    process_domains(input_domains, args.output)

if __name__ == "__main__":
    main()
