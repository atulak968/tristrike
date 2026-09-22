"""
Scope Enforcement & Validation
Prevents out-of-scope requests.
"""

from urllib.parse import urlparse
import fnmatch

class ScopeManager:
    def __init__(self, target: str, scope_patterns: list = None):
        self.target = target
        self.target_host = urlparse(target if "://" in target else f"https://{target}").netloc.split(":")[0]
        self.scope_patterns = scope_patterns or [self.target_host, f"*.{self.target_host}"]

    def is_in_scope(self, url_or_host: str) -> bool:
        if "://" in url_or_host:
            host = urlparse(url_or_host).netloc.split(":")[0]
        else:
            host = url_or_host.split(":")[0].split("/")[0]

        host = host.lower().strip()
        for pat in self.scope_patterns:
            pat = pat.lower().strip()
            if pat == host or fnmatch.fnmatch(host, pat):
                return True
        return False
