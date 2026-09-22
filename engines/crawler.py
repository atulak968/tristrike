"""
Deep Discovery & Crawler Engine
Discovers sensitive routes, API endpoints, and filters out static noise.
"""

import requests
import re
from urllib.parse import urljoin, urlparse

class CrawlerEngine:
    def __init__(self, scope_mgr):
        self.scope = scope_mgr
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False

    def is_static_asset(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        static_exts = [
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", 
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
            ".pdf", ".zip", ".tar.gz", ".map"
        ]
        return any(path.endswith(ext) for ext in static_exts)

    def crawl(self, base_url: str) -> dict:
        discovered_urls = set()
        endpoints_with_params = []
        hidden_paths = []

        visited = set()
        queue = [base_url]

        # 30+ High-value sensitive endpoints & API targets
        high_value_wordlist = [
            "robots.txt", "sitemap.xml", ".well-known/security.txt",
            ".env", "config.json", "swagger.json", "swagger-ui.html", "api-docs",
            "api", "api/v1", "api/v2", "graphql", "graphiql",
            "admin", "administrator", "login", "register", "signup",
            "actuator", "actuator/health", "actuator/env",
            "debug", "status", "phpinfo.php", "server-status",
            "rest/products/search", "rest/user/login", "api/Products", "api/Users"
        ]

        # 1. Probing sensitive paths
        for path in high_value_wordlist:
            target_path = urljoin(base_url, path)
            try:
                r = self.session.get(target_path, timeout=4, allow_redirects=False)
                if r.status_code in (200, 201, 301, 302, 401, 403):
                    hidden_paths.append({
                        "path": target_path,
                        "status": r.status_code,
                        "size": len(r.content)
                    })
                    discovered_urls.add(target_path)
            except Exception:
                pass

        # 2. Extract links and parameters from pages & JavaScript files
        for current_url in queue[:25]:
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                resp = self.session.get(current_url, timeout=6)
                text = resp.text

                # Match href, src, and JS route patterns
                matches = re.findall(r'(?:href|src|url|path)=["\']([^"\'\s>]+)["\']', text, re.IGNORECASE)
                js_routes = re.findall(r'["\'](/(?:api|rest|v1|v2|graphql)[a-zA-Z0-9_\-\/]+)["\']', text)
                matches.extend(js_routes)

                for link in matches:
                    if link.startswith("#") or link.startswith("javascript:") or link.startswith("data:"):
                        continue
                    full = urljoin(current_url, link)
                    if self.scope.is_in_scope(full):
                        discovered_urls.add(full)
                        if "?" in full and "=" in full:
                            # Only include dynamic endpoints (skip static assets like .css?v=1)
                            if not self.is_static_asset(full) and full not in endpoints_with_params:
                                endpoints_with_params.append(full)
            except Exception:
                pass

        # If no dynamic parameters discovered from HTML, create heuristic parameter targets on live routes
        if not endpoints_with_params:
            candidate_routes = [u for u in discovered_urls if not self.is_static_asset(u)]
            if not candidate_routes:
                candidate_routes = [base_url]
            for ep in candidate_routes[:5]:
                for param in ["q", "id", "search", "url", "redirect", "file", "category"]:
                    test_ep = f"{ep}?{param}=test"
                    if test_ep not in endpoints_with_params:
                        endpoints_with_params.append(test_ep)

        return {
            "all_endpoints": list(discovered_urls),
            "param_endpoints": endpoints_with_params,
            "hidden_paths": hidden_paths
        }
