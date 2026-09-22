"""
Crawler & Endpoint Discovery Engine
Discovers HTML links, JavaScript routes, parameters, and sensitive paths.
"""

import requests
import re
from urllib.parse import urljoin, urlparse

class CrawlerEngine:
    def __init__(self, scope_mgr):
        self.scope = scope_mgr
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        self.session.verify = False

    def crawl(self, base_url: str, depth: int = 2) -> dict:
        discovered_urls = set()
        endpoints_with_params = []
        hidden_paths = []

        visited = set()
        queue = [base_url]

        # Common Juice Shop & Modern Web API routes
        sensitive_wordlist = [
            "robots.txt", "sitemap.xml", ".well-known/security.txt",
            "api/Products", "api/Users", "api/BasketItems", "api/Feedbacks",
            "rest/products/search", "rest/user/login", "rest/admin/application-version",
            "api", "api/v1", "api/v2", "admin", "swagger.json",
            "graphql", "login", "register", "config.json"
        ]

        # 1. Probing sensitive / API paths
        for path in sensitive_wordlist:
            target_path = urljoin(base_url, path)
            try:
                r = self.session.get(target_path, timeout=5, allow_redirects=False)
                if r.status_code in (200, 201, 301, 302, 401, 403):
                    hidden_paths.append({
                        "path": target_path,
                        "status": r.status_code,
                        "size": len(r.content)
                    })
                    discovered_urls.add(target_path)
                    if "search" in path:
                        endpoints_with_params.append(f"{target_path}?q=apple")
            except Exception:
                pass

        # 2. Extract links and parameters from pages & JavaScript files
        for current_url in queue[:20]:
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                resp = self.session.get(current_url, timeout=8)
                text = resp.text

                # Match href, src, and JS route patterns (e.g., "/api/...", "rest/...")
                matches = re.findall(r'(?:href|src|url|path)=["\']([^"\'\s>]+)["\']', text, re.IGNORECASE)
                js_routes = re.findall(r'["\'](/(?:api|rest)/[a-zA-Z0-9_\-\/]+)["\']', text)
                matches.extend(js_routes)

                for link in matches:
                    if link.startswith("#") or link.startswith("javascript:") or link.startswith("data:"):
                        continue
                    full = urljoin(current_url, link)
                    if self.scope.is_in_scope(full):
                        discovered_urls.add(full)
                        if "?" in full and "=" in full:
                            if full not in endpoints_with_params:
                                endpoints_with_params.append(full)
            except Exception:
                pass

        return {
            "all_endpoints": list(discovered_urls),
            "param_endpoints": endpoints_with_params,
            "hidden_paths": hidden_paths
        }
