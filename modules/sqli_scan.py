from .base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning, print_error
from urllib.parse import urlencode

class SQLiScanner(VulnerabilityScanner):
    """
    Performs basic SQL Injection testing on identified forms.
    """
    def __init__(self, target_url, session, forms):
        super().__init__(target_url, session)
        self.forms = forms

    def scan(self):
        print_info(f"Starting SQL Injection Scan on {len(self.forms)} forms...")
        
        # Expanded SQLi payloads dictionary
        payloads = {
            "Classic OR": "' OR '1'='1",
            "Classic OR Comment": "' OR '1'='1' -- ",
            "Union Select": "' UNION SELECT 1,2,3,4,5 -- ",
            "Error Based": "'", 
            "Time Based": "1'; WAITFOR DELAY '0:0:5'--",
            "Boolean True": "' AND 1=1 -- ",
            "Boolean False": "' AND 1=2 -- "
        }
        
        # Expanded error signatures
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sqlexception",
            "valid postgresql result",
            "odbc driver",
            "sqlserver jdbc driver",
            "ora-01756"
        ]

        for form in self.forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            print_info(f"Testing form at {action}...")

            # 1. Error-Based & Classic Injection
            for p_name, payload in payloads.items():
                if "Boolean" in p_name: continue # Skip boolean for this loop

                data = {}
                for input_field in inputs:
                    if input_field["type"] not in ["submit", "button", "image"]:
                        data[input_field["name"]] = payload
                
                try:
                    res = self._send_request(action, method, data)
                    content = res.text.lower()
                    
                    found = False
                    for error in sql_errors:
                        if error in content:
                            print_error(f"SQLi Found ({p_name}) in {action}")
                            self.add_finding(
                                "SQL Injection (Error-Based)",
                                f"Form at {action} returned SQL error with payload: {payload}",
                                "High",
                                url=action,
                                payload=payload,
                                evidence=error,
                                poc=self._generate_poc(action, method, data)
                            )
                            found = True
                            break
                    if found: break 
                except Exception as e:
                    print_warning(f"Error testing {p_name} on {action}: {e}")

            # 2. Boolean-Based Blind Injection
            # We need to pick ONE injection point to test boolean logic properly
            target_input = next((i["name"] for i in inputs if i["type"] not in ["submit", "button", "image"]), None)
            
            if target_input:
                try:
                    # Baseline request (normal)
                    base_data = {i["name"]: "test" for i in inputs if i["type"] not in ["submit", "button", "image"]}
                    base_res = self._send_request(action, method, base_data)
                    base_len = len(base_res.text)

                    # True Condition
                    true_data = base_data.copy()
                    true_data[target_input] = "test" + payloads["Boolean True"]
                    true_res = self._send_request(action, method, true_data)
                    
                    # False Condition
                    false_data = base_data.copy()
                    false_data[target_input] = "test" + payloads["Boolean False"]
                    false_res = self._send_request(action, method, false_data)

                    # Logic: True response should differ significantly from False response
                    # Comparison logic can be length or content similarity
                    if abs(len(true_res.text) - len(false_res.text)) > 50 and \
                       abs(len(true_res.text) - base_len) < 50:
                        
                        print_error(f"Boolean SQLi Found in {action}")
                        self.add_finding(
                            "SQL Injection (Boolean-Blind)",
                            f"Form at {action} responded differently to TRUE/FALSE payloads.",
                            "Critical",
                            url=action,
                            payload=payloads["Boolean True"] + " vs " + payloads["Boolean False"],
                            evidence="Different response lengths for Boolean conditions",
                            poc=self._generate_poc(action, method, true_data)
                        )
                except Exception as e:
                    print_warning(f"Error testing blind SQLi on {action}: {e}")

        return self.vulnerabilities

    def _send_request(self, action, method, data):
        if method == "post":
            return self.session.post(action, data=data, timeout=5)
        else:
            return self.session.get(action, params=data, timeout=5)

    def _generate_poc(self, action, method, data):
        if method == "post":
             return f"curl -X POST -d '{urlencode(data)}' '{action}'"
        else:
             return f"{action}?{urlencode(data)}"
