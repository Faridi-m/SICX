import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

def crawl_urls(base_url, max_pages=30):
    visited = set()
    to_visit = [base_url]
    found = set()

    # Check if the initial URL has parameters
    if urlparse(base_url).query:
        found.add(base_url)

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, timeout=5)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(base_url, a["href"].split('#')[0])
                if link.startswith(base_url):
                    to_visit.append(link)
                    if urlparse(link).query:
                        found.add(link)
        except:
            continue

    return list(found)
