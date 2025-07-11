#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
    CTFR - A Certificate Transparency Log Subdomain Enumerator
------------------------------------------------------------------------------
"""

## # LIBRARIES # ##
import re
import requests
import argparse
import os
import sys
import logging

## # CONTEXT VARIABLES # ##
__version__ = "1.2" # Using __version__ for standard versioning
CRT_SH_URL = "https://crt.sh/?q=%.{target}&output=json"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

## # MAIN FUNCTIONS # ##

def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="CTFR: A tool for subdomain enumeration using crt.sh certificate transparency logs.",
        formatter_class=argparse.RawTextHelpFormatter # For better help message formatting if needed
    )
    parser.add_argument(
        '-f', '--file',
        type=str,
        required=True,
        help="File containing the list of domains (one per line)."
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        help="Output file to save the discovered subdomains."
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit."
    )
    return parser.parse_args()

def banner():
    """
    Display the tool's banner.
    """ # Removed "Fixed SyntaxWarning: invalid escape sequence '\ '" from docstring
    global __version__ # Use global for __version__ if modifying it inside banner, though it's typically a constant
    b = r'''
          ____ _____ _____ ____  
         / ___|_  _| ___| _ \  
        | |     | | | |_  | |_) |
        | |___  | | |  _| |  _ <  
         \____| |_| |_|   |_| \_\
    
    Version {} - Hey don't miss AXFR!
    Made by NC-Security
    '''.format(__version__)
    print(b)

def clear_url(target):
    """
    Clean the domain URL (remove 'www.' and the path).
    Ensures consistent output format for the main domain.
    """ # Removed "Fixed SyntaxWarning: invalid escape sequence '\.'" from docstring
    # Remove protocol if present (http://, https://)
    target = re.sub(r'https?://', '', target, flags=re.IGNORECASE)
    # Remove 'www.' prefix at the beginning of the string, case-insensitively
    target = re.sub(r'^www\.', '', target, flags=re.IGNORECASE)
    # Take only the first part before any '/'
    target = target.split('/')[0].strip()
    return target.lower() # Standardize to lowercase

def save_subdomains(subdomain, output_file):
    """
    Save subdomains to the output file.
    Robust error handling for file operations.
    """
    try:
        with open(output_file, "a") as f:
            f.write(subdomain + '\n')
    except IOError as e:
        logger.error(f"Failed to write to output file '{output_file}': {e}")

def get_subdomains(target):
    """
    Fetch subdomains from crt.sh for the given target domain.
    Improved error handling for network requests and JSON parsing.
    """
    subdomains = []
    try:
        req = requests.get(CRT_SH_URL.format(target=target), timeout=10) # Added timeout
        req.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # crt.sh can sometimes return an empty list or malformed JSON if no results
        # or an issue occurred on their end.
        if not req.text.strip():
            logger.info(f"No certificate data found for {target} on crt.sh.")
            return subdomains
            
        data = req.json()
        
        for value in data:
            # Ensure 'name_value' key exists
            if 'name_value' in value:
                # crt.sh can return comma-separated names, split and add each
                names = value['name_value'].split('\n')
                for name in names:
                    if name.strip(): # Ensure it's not an empty string
                        subdomains.append(name.strip())

    except requests.exceptions.Timeout:
        logger.error(f"Request to crt.sh timed out for {target}.")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error to crt.sh for {target}: {e}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error occurred for {target} ({e.response.status_code}): {e.response.text}")
    except ValueError as e: # Catch JSON decoding errors
        logger.error(f"Failed to decode JSON response from crt.sh for {target}: {e}. Response: {req.text[:200]}...") # Log partial response for debug
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching subdomains for {target}: {e}")

    # Use a set for efficient duplicate removal, then convert to list and sort
    return sorted(list(set(subdomains)))

def filter_subdomains(subdomains, main_domain):
    """
    Filter out wildcard subdomains (containing '*') and subdomains that are
    not directly related to the main domain (e.g., other TLDs or completely different domains).
    Also removes the main domain itself if present.
    """
    filtered_subdomains = set() # Use a set for efficiency during filtering
    
    # Ensure main_domain is in lowercase for consistent comparison
    main_domain_lower = main_domain.lower()

    for subdomain in subdomains:
        subdomain_lower = subdomain.lower()

        # 1. Remove subdomains that contain '*' (wildcard)
        if '*' in subdomain_lower:
            continue
        
        # 2. Remove the main domain itself
        if subdomain_lower == main_domain_lower:
            continue

        # 3. Ensure the subdomain actually ends with the main domain
        # This prevents picking up 'otherdomain.com' if 'example.com' was the target
        if not subdomain_lower.endswith(f".{main_domain_lower}"):
            # A special case might be a domain that is exactly 'main_domain.com' if the input was just 'main_domain'
            # But generally, we're looking for 'sub.main_domain.com'
            # We already handled the exact main_domain_lower match above.
            continue
            
        # Add to the set
        filtered_subdomains.add(subdomain)
    
    return sorted(list(filtered_subdomains))

def load_domains_from_file(file_path):
    """
    Load domains from a file and return a cleaned list.
    Robust error handling for file existence and reading.
    """
    if not os.path.exists(file_path):
        logger.error(f"Input file not found: {file_path}")
        sys.exit(1) # Exit if the input file is critical and missing

    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f: # Specify encoding for broader compatibility
            for line in f:
                stripped_line = line.strip()
                if stripped_line:  # Only add non-empty lines after stripping
                    domains.append(stripped_line)
    except IOError as e:
        logger.error(f"Error reading input file '{file_path}': {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading domains from '{file_path}': {e}")
        sys.exit(1)
        
    if not domains:
        logger.warning(f"Input file '{file_path}' is empty or contains no valid domains.")
        sys.exit(0) # Exit gracefully if no domains to process

    return domains

def process_domains(domains, output_file):
    """
    Process each domain to find subdomains, filter them, and save them to a file if necessary.
    """
    total_found_subdomains = 0
    for domain in domains:
        target = clear_url(domain)
        logger.info(f"\n[!] ---- Processing: {target} ---- [!]")

        subdomains = get_subdomains(target)

        if not subdomains:
            logger.info(f"No subdomains found on crt.sh for {target}.")
            continue # Move to the next domain

        filtered_subdomains = filter_subdomains(subdomains, target)
        
        if not filtered_subdomains:
            logger.info(f"No unique or valid subdomains found after filtering for {target}.")
            continue

        logger.info(f"Found {len(filtered_subdomains)} unique subdomains for {target}:")
        for subdomain in filtered_subdomains:
            print(f"[-] {subdomain}")
            if output_file is not None:
                save_subdomains(subdomain, output_file)
        total_found_subdomains += len(filtered_subdomains)

    logger.info(f"\n\n[!] Processing complete. Total unique subdomains found: {total_found_subdomains}")
    logger.info("[!] Have a nice day! ;)")


def main():
    """
    Main function to execute the script.
    """
    banner()
    args = parse_args()

    # Load domains from the file
    input_domains = load_domains_from_file(args.file)

    # Process domains
    process_domains(input_domains, args.output)

if __name__ == "__main__":
    main()