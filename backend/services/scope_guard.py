"""Scope guard — enforces in-scope/out-of-scope rules for all recon actions."""

import json
import re
import fnmatch
from urllib.parse import urlparse


class ScopeGuard:
    def __init__(self, in_scope_patterns: list[str], out_scope_patterns: list[str]):
        self.in_scope = in_scope_patterns
        self.out_scope = out_scope_patterns

    def _extract_hostname(self, url_or_host: str) -> str:
        """Extract hostname from a URL or return as-is if already a hostname."""
        if url_or_host.startswith(("http://", "https://")):
            return urlparse(url_or_host).hostname or url_or_host
        # Strip protocol-less paths
        return url_or_host.split("/")[0].split(":")[0]

    def _matches_pattern(self, hostname: str, pattern: str) -> bool:
        """Check if a hostname matches a scope pattern (supports wildcards)."""
        # Normalize: strip protocol from pattern if present
        clean = self._extract_hostname(pattern)
        return fnmatch.fnmatch(hostname.lower(), clean.lower())

    def is_in_scope(self, url_or_host: str) -> tuple[bool, str]:
        """
        Returns (in_scope: bool, reason: str).
        A target is in-scope if it matches at least one in-scope pattern
        AND does not match any out-of-scope pattern.
        """
        hostname = self._extract_hostname(url_or_host)

        # Check out-of-scope first (takes priority)
        for pattern in self.out_scope:
            if self._matches_pattern(hostname, pattern):
                return False, f"Matches out-of-scope pattern: {pattern}"

        # Must match at least one in-scope pattern
        if not self.in_scope:
            return True, "No in-scope restrictions defined"

        for pattern in self.in_scope:
            if self._matches_pattern(hostname, pattern):
                return True, f"Matches in-scope pattern: {pattern}"

        return False, f"No in-scope pattern matches {hostname}"


def build_guard_from_session(scope_session) -> ScopeGuard:
    """Build a ScopeGuard from a ScopeSession ORM object."""
    try:
        in_patterns = json.loads(scope_session.in_scope_patterns or "[]")
    except (json.JSONDecodeError, TypeError):
        in_patterns = []
    try:
        out_patterns = json.loads(scope_session.out_scope_patterns or "[]")
    except (json.JSONDecodeError, TypeError):
        out_patterns = []

    # Always add the primary domain as in-scope if patterns are empty
    if not in_patterns and scope_session.target_domain:
        in_patterns = [f"*.{scope_session.target_domain}", scope_session.target_domain]

    return ScopeGuard(in_patterns, out_patterns)
