# modules/subdomain_enum.py
import requests
from typing import List, Set
import logging
import urllib.parse
from utils.cache import get_from_cache, save_to_cache

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"

def query_crtsh(domain: str) -> List[dict]:
    """
    Query crt.sh JSON output for certificates containing the domain.
    Returns parsed JSON list (may be empty); handles errors gracefully.
    """
    # Use %25.<domain> to search for subdomains (percent-encoded % for wildcard)
    q = f"%25.{domain}"
    params = {"q": q, "output": "json"}
    try:
        # crt.sh blocks some clients; set a common User-Agent and a short timeout
        headers = {"User-Agent": "Mozilla/5.0 (compatible; ReconWebUI/1.0)"}
        r = requests.get(CRT_SH_URL, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        # Sometimes crt.sh returns invalid json if there are no results; catch that
        try:
            data = r.json()
            if isinstance(data, list):
                return data
            else:
                return []
        except ValueError:
            # not JSON (empty or HTML), return empty list
            logger.debug("crt.sh returned non-JSON for domain %s", domain)
            return []
    except Exception as e:
        logger.warning("crt.sh query failed for %s: %s", domain, e)
        return []

def extract_names_from_crtsh(records: List[dict]) -> Set[str]:
    """
    Given crt.sh JSON objects, pull out common_name and name_value fields.
    Returns a set of domain names (may include duplicates/wildcards).
    """
    names = set()
    for entry in records:
        # common_name sometimes present
        cn = entry.get("common_name")
        if cn:
            names.add(cn.strip().lower())
        nv = entry.get("name_value")
        if nv:
            # name_value can be newline-separated list
            for part in str(nv).splitlines():
                if part:
                    names.add(part.strip().lower())
    return names

def find_subdomains(domain: str, use_cache: bool = True) -> list[str]:
    """
    Query crt.sh for subdomains of a given domain.
    Uses cache to avoid repeated lookups.
    """
    cache_key = f"subdomains:{domain.lower()}"
    if use_cache:
        cached = get_from_cache(cache_key)
        if cached is not None:
            return cached

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    subdomains.add(sub.strip())
        results = sorted(s for s in subdomains if s)
        if use_cache:
            save_to_cache(cache_key, results)
        return results
    except Exception:
        return []
