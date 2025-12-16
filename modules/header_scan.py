from .base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning

class HeaderScanner(VulnerabilityScanner):
    """
    Scans for missing security headers.
    """
    def scan(self):
        print_info(f"Starting Header Scan on {self.target_url}...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # List of headers to check
            security_headers = {
                "X-Frame-Options": "Medium",
                "Content-Security-Policy": "High",
                "Strict-Transport-Security": "High",
                "X-Content-Type-Options": "Low"
            }

            for header, severity in security_headers.items():
                if header not in headers:
                    print_info(f"Missing Header: {header}")
                    self.add_finding(
                        "Missing Security Header",
                        f"The header '{header}' is missing from the response.",
                        severity
                    )
                else:
                    print_info(f"Found Header: {header}")

        except Exception as e:
            print_warning(f"Header scan failed: {e}")

        return self.vulnerabilities
