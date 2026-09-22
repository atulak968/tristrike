"""
Recon Engine (Subdomains, DNS, Ports, Tech Stack)
"""

import requests
import socket
import re
import concurrent.futures
from urllib.parse import urlparse

class ReconEngine:
    def __init__(self, scope_mgr):
        self.scope = scope_mgr

    def run(self, target: str) -> dict:
        host = self.scope.target_host
        results = {
            "subdomains": [host],
            "live_hosts": [],
            "open_ports": [],
            "tech_stack": []
        }

        # 1. Passive Subdomain Enumeration via crt.sh
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=10)
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if "*" not in sub and self.scope.is_in_scope(sub):
                            if sub not in results["subdomains"]:
                                results["subdomains"].append(sub)
        except Exception:
            pass

        # 2. Port Probe on main host
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
        for p in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                if s.connect_ex((host, p)) == 0:
                    results["open_ports"].append(p)
                s.close()
            except Exception:
                pass

        # 3. HTTP Probe & Tech Fingerprinting
        url = target if "://" in target else f"https://{host}"
        try:
            resp = requests.get(url, timeout=8, verify=False, allow_redirects=True)
            results["live_hosts"].append(url)
            headers_str = " ".join([f"{k}: {v}" for k, v in resp.headers.items()]).lower()
            body_sample = resp.text[:4000].lower()

            tech_rules = {
                "Cloudflare": ["cf-ray", "cloudflare"],
                "Nginx": ["nginx"],
                "Apache": ["apache"],
                "Express.js": ["x-powered-by: express"],
                "React": ["react", "react-dom", "_react"],
                "Angular": ["ng-version", "angular"],
                "Vue.js": ["vue", "v-cloak"],
                "PHP": ["x-powered-by: php", "php/"],
                "Django": ["csrftoken"],
                "Laravel": ["laravel_session", "x-powered-by: laravel"],
                "Node.js": ["x-powered-by: nodejs"]
            }

            for tech, signatures in tech_rules.items():
                if any(sig in headers_str or sig in body_sample for sig in signatures):
                    if tech not in results["tech_stack"]:
                        results["tech_stack"].append(tech)

        except Exception:
            pass

        return results
