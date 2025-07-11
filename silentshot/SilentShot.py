#!/usr/bin/env python3
import asyncio
import os
import sys
import random
import time
import shutil
import glob
from typing import List, Dict, Optional
from pathlib import Path

import typer
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from playwright._impl._driver import compute_driver_executable

app = typer.Typer(help="SilentShot – Headless Web Screenshot CLI Tool by NC-Security")

# -------------------- Constants --------------------
DEFAULT_CONFIG = {
    "width": 1440,
    "height": 900,
    "tabs": 4,
    "timeout": 100,
    "delay": 0,
    "jitter": 0,
    "max_retries": 3,
    "fullpage": False,
    "screenshot_type": "png",
    "silent": False
}

# -------------------- Branding --------------------
def banner():
    print("""
    ███████╗██╗██╗     ███████╗███╗   ██╗████████╗███████╗██╗  ██╗ ██████╗ ████████╗
    ██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
    ███████╗██║██║     █████╗  ██╔██╗ ██║   ██║   ███████╗███████║██║   ██║   ██║   
    ╚════██║██║██║     ██╔══╝  ██║╚██╗██║   ██║   ╚════██║██╔══██║██║   ██║   ██║   
    ███████║██║███████╗███████╗██║ ╚████║   ██║   ███████║██║  ██║╚██████╔╝   ██║   
    ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   
                                                                                    
                                SilentShot – Headless Web Screenshot CLI Tool by NC-Security
    """)

# -------------------- Utility Functions --------------------
def sanitize_url(url: str) -> str:
    """Sanitize URL to create safe filenames"""
    return (url.replace("://", "_")
              .replace("/", "_")
              .replace("?", "_")
              .replace(":", "_")
              .replace("*", "_")
              .replace('"', "_")
              .replace("'", "_"))

def parse_urls(url: Optional[str], file_path: Optional[str], use_stdin: bool) -> List[str]:
    """Parse URLs from various input sources"""
    raw_urls = []
    
    if url:
        raw_urls.append(url.strip())
    if file_path:
        with open(file_path) as f:
            raw_urls.extend(line.strip() for line in f if line.strip())
    if use_stdin and not sys.stdin.isatty():
        raw_urls.extend(line.strip() for line in sys.stdin if line.strip())

    # Ensure URLs have proper scheme and remove duplicates
    urls = []
    for u in raw_urls:
        if not u.startswith(("http://", "https://")):
            u = f"https://{u}"
        urls.append(u)
    
    return list(set(urls))

def get_chromium_path() -> Optional[str]:
    """Find Chromium binary path with priority to system-installed versions"""
    # Check common system paths first
    for path in ["/usr/bin/chromium", "/usr/bin/chromium-browser",
                 "/usr/local/bin/chromium", "/usr/local/bin/chromium-browser"]:
        if shutil.which(path):
            return path
    
    # Check Playwright's installed Chromium
    playwright_path = Path.home() / ".cache/ms-playwright/chromium-*/chrome-linux/chrome"
    matches = glob.glob(str(playwright_path))
    if matches:
        return matches[0]
    
    # Fallback to Playwright driver
    try:
        return compute_driver_executable()
    except:
        return None

async def jitter_delay(seconds: int) -> None:
    """Add random delay between requests"""
    if seconds > 0:
        await asyncio.sleep(random.uniform(0, seconds))

# -------------------- Core Screenshot Functionality --------------------
async def process_url(context, sem, url: str, config: Dict) -> None:
    """Process a single URL to capture screenshot"""
    for attempt in range(1, config["max_retries"] + 1):
        try:
            async with sem:
                page = await context.new_page()
                
                try:
                    start_time = time.monotonic()
                    await page.goto(url, timeout=config["timeout"] * 1000)
                    await asyncio.sleep(config["delay"])

                    screenshot_name = f"{sanitize_url(url)}.{config['screenshot_type']}"
                    screenshot_path = Path(config["outdir"]) / screenshot_name
                    
                    await page.screenshot(
                        path=str(screenshot_path),
                        full_page=config["fullpage"],
                        type=config["screenshot_type"]
                    )

                    if not config["silent"]:
                        elapsed = time.monotonic() - start_time
                        print(f"[+] Success ({elapsed:.2f}s): {url}")
                    return
                finally:
                    await page.close()
                    
        except PlaywrightTimeout:
            if not config["silent"]:
                print(f"[!] Timeout ({attempt}/{config['max_retries']}): {url}")
        except Exception as e:
            if not config["silent"]:
                print(f"[!] Error ({attempt}/{config['max_retries']}): {url} - {str(e)}")
        
        await jitter_delay(config["jitter"])
    
    print(f"[x] Failed after {config['max_retries']} attempts: {url}")

# -------------------- Main CLI Entry --------------------
@app.command()
def capture(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Single target URL"),
    file_path: Optional[str] = typer.Option(None, "--file-path", "-f", help="File with list of URLs"),
    stdin: bool = typer.Option(False, "--stdin", help="Read URLs from stdin"),
    outdir: str = typer.Option("SilentShot", "--outdir", "-o", help="Output directory"),
    width: int = typer.Option(DEFAULT_CONFIG["width"], "--width", "-x", help="Viewport width"),
    height: int = typer.Option(DEFAULT_CONFIG["height"], "--height", "-y", help="Viewport height"),
    tabs: int = typer.Option(DEFAULT_CONFIG["tabs"], "--tabs", "-t", help="Number of concurrent tabs"),
    timeout: int = typer.Option(DEFAULT_CONFIG["timeout"], "--timeout", help="Timeout per URL in seconds"),
    delay: int = typer.Option(DEFAULT_CONFIG["delay"], "--delay", help="Delay before screenshot (sec)"),
    jitter_time: int = typer.Option(DEFAULT_CONFIG["jitter"], "--jitter", help="Random delay between URLs"),
    max_retries: int = typer.Option(DEFAULT_CONFIG["max_retries"], "--max-retries", help="Retry count on failure"),
    fullpage: bool = typer.Option(DEFAULT_CONFIG["fullpage"], "--fullpage", help="Capture full page"),
    screenshot_type: str = typer.Option(
        DEFAULT_CONFIG["screenshot_type"],
        "--screenshot-type",
        help="Image format (png, jpeg, or webp)",
        case_sensitive=False
    ),
    binary_path: Optional[str] = typer.Option(
        None,
        "--binary-path", "-b",
        help="Path to Chromium binary. Auto-detected if not specified"
    ),
    proxy_auth: Optional[str] = typer.Option(None, "--proxy-auth", help="Proxy in user:pass@ip:port format"),
    proxy_ip: Optional[str] = typer.Option(None, "--proxy-ip", help="Proxy IP address"),
    proxy_port: Optional[int] = typer.Option(None, "--proxy-port", help="Proxy port"),
    proxy_type: str = typer.Option("http", "--proxy-type", help="Proxy type: http or socks5"),
    silent: bool = typer.Option(DEFAULT_CONFIG["silent"], "--silent", help="Suppress success logs")
):
    """Capture screenshots of websites in headless mode"""
    if not silent:
        banner()

    # Validate screenshot type
    if screenshot_type.lower() not in ("png", "jpeg", "webp"):
        raise typer.BadParameter("Screenshot type must be png, jpeg, or webp")

    # Prepare output directory
    os.makedirs(outdir, exist_ok=True)
    
    # Parse URLs from all sources
    urls = parse_urls(url, file_path, stdin)
    if not urls:
        raise typer.BadParameter("No URLs provided via any input method")

    # Configure proxy if provided
    proxy = None
    if proxy_ip and proxy_port:
        proxy = {"server": f"{proxy_type}://{proxy_ip}:{proxy_port}"}

    # ====== ADD THIS PROXY HANDLING CODE ======
    proxy = None
    if proxy_auth:
        try:
            creds, addr = proxy_auth.split('@')
            proxy_user, proxy_pass = creds.split(':')
            proxy_ip, proxy_port = addr.split(':')
            proxy = {
                "server": f"{proxy_type}://{proxy_ip}:{proxy_port}",
                "username": proxy_user,
                "password": proxy_pass
            }
        except ValueError:
            raise typer.BadParameter("Proxy format must be user:pass@ip:port")
    elif proxy_ip and proxy_port:
        proxy = {
            "server": f"{proxy_type}://{proxy_ip}:{proxy_port}"
        }
        
    # Determine Chromium path
    chromium_path = binary_path or get_chromium_path()
    if not chromium_path:
        raise typer.Exit("Could not find Chromium binary. Please specify with --binary-path")

    # Prepare configuration
    config = {
        "outdir": outdir,
        "width": width,
        "height": height,
        "tabs": tabs,
        "timeout": timeout,
        "delay": delay,
        "jitter": jitter_time,
        "max_retries": max_retries,
        "fullpage": fullpage,
        "screenshot_type": screenshot_type.lower(),
        "silent": silent
    }

    async def runner():
        """Main async runner function"""
        sem = asyncio.Semaphore(config["tabs"])
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                executable_path=chromium_path,
                args=[
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-setuid-sandbox",
                    "--disable-software-rasterizer",
                    "--disable-accelerated-2d-canvas",
                    "--disable-accelerated-video-decode",
                    "--disable-background-timer-throttling",
                    "--disable-renderer-backgrounding"
                ],
                proxy=proxy,
                timeout=config["timeout"] * 1000
            )
            
            context = await browser.new_context(
                viewport={"width": width, "height": height},
                ignore_https_errors=True,
                java_script_enabled=True
            )

            try:
                await asyncio.gather(*[
                    process_url(context, sem, u, config) for u in urls
                ])
            finally:
                await context.close()
                await browser.close()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        raise typer.Abort()

if __name__ == "__main__":
    app()