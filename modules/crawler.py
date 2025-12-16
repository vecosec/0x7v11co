import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from urllib.parse import urljoin, urlparse
from utils.colors import print_info, print_success, Colors

class Crawler:
    def __init__(self, target_url, session, max_depth=2):
        self.target_url = target_url
        self.session = session
        self.max_depth = max_depth
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.domain = urlparse(target_url).netloc

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.target_url

        if depth > self.max_depth:
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        self.urls_to_scan.add(url)
        
        # Print progress only for top-level or significant finds to avoid spam
        if depth <= 1:
            print_info(f"Crawling: {url} (Depth: {depth})")

        try:
            response = self.session.get(url, timeout=5)
            if response.status_code != 200:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    parsed_url = urlparse(full_url)
                    
                    # Only crawl internal links
                    if parsed_url.netloc == self.domain:
                        # Avoid static files that usually don't have vulnerabilities or forms
                        if not any(full_url.endswith(ext) for ext in ['.jpg', '.png', '.gif', '.css', '.js', '.pdf', '.svg']):
                            self.crawl(full_url, depth + 1)

        except Exception as e:
            # print(f"{Colors.WARNING} Error crawling {url}: {e}")
            pass

    def get_urls(self):
        print_info(f"Starting Crawler on {self.target_url} (Max Depth: {self.max_depth})...")
        self.crawl()
        print_info(f"Crawler finished. Found {len(self.urls_to_scan)} unique URLs.")
        return list(self.urls_to_scan)
