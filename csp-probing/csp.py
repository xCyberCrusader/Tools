import requests
from urllib.parse import urlparse
import re
import click
import json
import tldextract
from socket import gethostbyname, gaierror
from collections import defaultdict


class Domain:
    def __init__(self, domain=None, apex_domain=None, ip=None, raw_csp_url=None, available=None):
        self.domain = domain
        self.apex_domain = apex_domain
        self.ip = ip
        self.raw_csp_url = raw_csp_url
        self.available = available


def fetch_csp_header(url):
    """
    Fetches CSP headers from a given URL. Automatically adds 'https://' if the scheme is missing.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # Default to HTTPS
        print(f"[INFO] No scheme found. Assuming HTTPS: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        headers = response.headers
        csp_header = headers.get("Content-Security-Policy", "")
        csp_report_only = headers.get("content-security-policy-report-only", "")

        if not csp_header and not csp_report_only:
            print(f"[INFO] No CSP header found for {url}")
            return None
        return csp_header + " " + csp_report_only

    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch headers for {url}: {e}")
        return None


def extract_domains(csp_header):
    """
    Extracts valid domains from the CSP header using regex and tldextract.
    """
    domains = []
    if csp_header:
        # Regex to match URLs and hostnames in CSP
        domain_pattern = r"(?:https?:\/\/)?(?:\*\.|www\.)?([\w\.-]+\.\w+)"
        matches = re.findall(domain_pattern, csp_header)

        # Deduplicate and process matches
        seen = set()
        for match in matches:
            if match not in seen:
                seen.add(match)
                ext = tldextract.extract(match)
                domain = ".".join([ext.subdomain, ext.domain, ext.suffix]).strip(".")
                apex_domain = ".".join([ext.domain, ext.suffix])
                domains.append(Domain(domain=domain, apex_domain=apex_domain, raw_csp_url=match))

    return domains


def resolve_domains(domains):
    """
    Resolves IP addresses for extracted domains.
    """
    for domain in domains:
        try:
            ip_address = gethostbyname(domain.domain)
            domain.ip = ip_address
            print(f"[RESOLVED] {domain.domain} -> {domain.ip}")
        except gaierror:
            domain.ip = None
            print(f"[UNRESOLVED] {domain.domain} has no A record.")
    return domains


def check_domains_availability(domains, cache=None):
    """
    Checks WHOIS information for domain availability with caching.
    """
    cache = cache or defaultdict(lambda: None)

    for domain in domains:
        if domain.apex_domain in cache:
            domain.available = cache[domain.apex_domain]
            continue

        try:
            import whois
            details = whois.whois(domain.apex_domain)
            is_available = details.get("status") is None
            domain.available = is_available
            cache[domain.apex_domain] = is_available
            status = "AVAILABLE" if is_available else "REGISTERED"
            print(f"[WHOIS] {domain.apex_domain} is {status}")
        except Exception as e:
            print(f"[WHOIS ERROR] {domain.apex_domain}: {e}")
            domain.available = False
            cache[domain.apex_domain] = False

    return domains


@click.command()
@click.option("--urls", "-u", multiple=True, help="One or more URLs to process.")
@click.option("--input-file", "-i", default=None, help="Path to a file containing URLs (one per line).")
@click.option("--resolve/--no-resolve", "-r", default=False, help="Enable/Disable DNS resolution")
@click.option("--check-availability/--no-check-availability", "--check", default=False, help="Check for domain availability")
@click.option("--output", "-o", default=None, help="Save results to a JSON file")
def main(urls, input_file, resolve, check_availability, output):
    """
    Main function to fetch, parse, and process CSP headers for multiple URLs.
    """
    # Collect URLs from command-line or file
    all_urls = list(urls)
    if input_file:
        try:
            with open(input_file, "r") as file:
                all_urls.extend([line.strip() for line in file if line.strip()])
        except FileNotFoundError:
            print(f"[ERROR] File not found: {input_file}")
            return

    if not all_urls:
        print("[ERROR] No URLs provided. Use --urls or --input-file.")
        return

    results = []

    # Process each URL
    for url in all_urls:
        print(f"[INFO] Fetching CSP header from {url}")
        csp_header = fetch_csp_header(url)

        if not csp_header:
            print(f"[INFO] Skipping {url} (no CSP header found).")
            continue

        print("[INFO] Extracting domains...")
        domains = extract_domains(csp_header)

        if resolve:
            print("[INFO] Resolving domain IPs...")
            domains = resolve_domains(domains)

        if check_availability:
            print("[INFO] Checking domain registration status...")
            domains = check_domains_availability(domains)

        results.extend(domains)

    # Save or print results
    if output:
        print(f"[INFO] Saving results to {output}")
        with open(output, "w") as file:
            json.dump([vars(ob) for ob in results], file, indent=4)
    else:
        print("[RESULTS]")
        for domain in results:
            print(f"Domain: {domain.domain}, Apex Domain: {domain.apex_domain}, IP: {domain.ip or 'Unresolved'}, Available: {domain.available}")


if __name__ == "__main__":
    main()
