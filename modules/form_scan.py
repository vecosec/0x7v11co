from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning

class FormScanner(VulnerabilityScanner):
    """
    Identifies and parses HTML forms.
    """
    def scan(self):
        print_info(f"Starting Form Scan on {self.target_url}...")
        forms_found = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")

            print_info(f"Found {len(forms)} forms.")

            for i, form in enumerate(forms):
                action = form.get("action")
                method = form.get("method", "get").lower()
                
                # Handle relative URLs
                action_url = urljoin(self.target_url, action) if action else self.target_url

                inputs = []
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    input_type = input_tag.get("type", "text")
                    if input_name:
                        inputs.append({"name": input_name, "type": input_type})

                form_details = {
                    "action": action_url,
                    "method": method,
                    "inputs": inputs
                }
                forms_found.append(form_details)
                print_info(f"Form #{i+1}: {method.upper()} to {action_url} with {len(inputs)} inputs")

            # We don't necessarily add vulnerabilities here, but we return the forms for other scanners
            # However, for the purpose of the report, we can log interesting findings if needed.
            # We don't necessarily add vulnerabilities here, but we return the forms for other scanners
            # However, for the purpose of the report, we can log interesting findings if needed.
            # (User feedback: Don't report this as a vulnerability issue)
            pass

        except Exception as e:
            print_warning(f"Form scan failed: {e}")

        return forms_found # Return raw data for other scanners to use
