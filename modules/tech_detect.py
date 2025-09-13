# modules/tech_detect.py
import re
from typing import List, Dict, Any, Optional
import requests
from requests.exceptions import RequestException
from urllib.parse import urljoin

# Simple signature-based rules (banner/header/body -> technology)
BANNER_SIGNATURES = {
    r"nginx": ["nginx"],
    r"apache": ["apache", "httpd"],
    r"iis": ["microsoft-iis", "microsoft httpapi"],
    r"lighttpd": ["lighttpd"],
    r"gunicorn": ["gunicorn"],
    r"uvicorn": ["uvicorn"],
    r"openresty": ["openresty"],
    r"tomcat": ["tomcat"],
    r"jetty": ["jetty"],
    r"node(?:js)?": ["node", "express", "nodejs"],
    r"php": ["php"],
    r"wordpress": ["wordpress", "wp-"],
    r"drupal": ["drupal"],
    r"joomla": ["joomla"],
    r"django": ["django"],
    r"flask": ["flask"],
    r"perl": ["perl"],
    r"rails|ruby": ["ruby", "rails"],
    r"asp.net": ["asp.net"],
    r"openssh": ["openssh", "ssh-"],
    r"smtp": ["exim", "postfix", "sendmail"],
    r"mysql": ["mysql"],
    r"postgres": ["postgres", "postgresql"],
    r"redis": ["redis"],
}

HEADER_SIGNATURES = {
    "server": [
        (r"nginx", "nginx"),
        (r"apache", "apache"),
        (r"iis", "microsoft-iis"),
        (r"openresty", "openresty"),
        (r"gunicorn", "gunicorn"),
        (r"tomcat", "tomcat"),
    ],
    "x-powered-by": [
        (r"PHP", "php"),
        (r"Express", "node/express"),
        (r"ASP.NET", "asp.net"),
        (r"WP Engine", "wordpress"),
    ]
}

HTML_META_SIGNATURES = {
    r"<meta[^>]*name=[\"']?generator[\"']?[^>]*content=[\"']?([^\"'>]+)": "meta_generator",
    r"wp-content": "wordpress",
    r"wp-includes": "wordpress",
    r"Joomla!": "joomla",
    r"Drupal": "drupal",
    r"Powered by Ruby": "ruby",
}

def _match_signatures_from_text(text: str, rules: Dict[str, List[str]]) -> List[str]:
    found = set()
    txt = (text or "").lower()
    for pattern, tags in rules.items():
        try:
            if re.search(pattern, txt, flags=re.I):
                for t in tags:
                    found.add(t)
        except re.error:
            # fallback: simple substring checks
            for t in tags:
                if t in txt:
                    found.add(t)
    return sorted(found)

def analyze_banners(banners: List[str]) -> List[str]:
    """
    Look for recognizable keywords in service banners.
    """
    found = set()
    for b in banners:
        if not b:
            continue
        for pat in BANNER_SIGNATURES:
            try:
                if re.search(pat, b, flags=re.I):
                    for tag in BANNER_SIGNATURES[pat]:
                        found.add(tag)
            except re.error:
                # fallback substring
                for tag in BANNER_SIGNATURES[pat]:
                    if tag in b.lower():
                        found.add(tag)
    return sorted(found)

def probe_http(host: str, use_https: bool = False, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Make an HTTP(S) request to the root and return headers and body snippet.
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    try:
        # allow insecure for self-signed certs
        r = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, headers={"User-Agent":"Mozilla/5.0 (compatible; ReconWebUI/1.0)"})
        headers = {k.lower(): v for k, v in r.headers.items()}
        text = r.text or ""
        snippet = text[:8000]  # cap
        return {"url": url, "status_code": r.status_code, "headers": headers, "body_snippet": snippet}
    except RequestException:
        return {"url": url, "error": "request_failed"}

def analyze_http_response(http_info: Dict[str, Any]) -> List[str]:
    found = set()
    if not http_info or "headers" not in http_info:
        return []
    headers = http_info["headers"]
    # header rules
    for header_name, rules in HEADER_SIGNATURES.items():
        v = headers.get(header_name)
        if v:
            for pat, tag in rules:
                if re.search(pat, v, flags=re.I):
                    found.add(tag)
    # body rules
    body = http_info.get("body_snippet", "") or ""
    for pattern, tag in HTML_META_SIGNATURES.items():
        if re.search(pattern, body, flags=re.I):
            found.add(tag)
    # meta generator extraction (if present)
    m = re.search(r"<meta[^>]*name=[\"']?generator[\"']?[^>]*content=[\"']?([^\"'>]+)", body, flags=re.I)
    if m:
        found.add("meta_generator:" + m.group(1).strip())
    return sorted(found)

def detect_technologies(host: str, port_scan_results: Optional[List[Dict[str, Any]]] = None, timeout: float = 4.0) -> Dict[str, Any]:
    """
    High level detection:
    - Use banners from port_scan_results to identify services.
    - If HTTP(S) ports appear open, probe them for headers/body and detect from those.
    Returns dict with 'banner_matches', 'http_probes', and 'guesses'.
    """
    guesses = set()
    banners = []
    if port_scan_results:
        for entry in port_scan_results:
            b = entry.get("banner") or ""
            if b:
                banners.append(b)
    # analyze banners
    banner_matches = analyze_banners(banners)
    for m in banner_matches:
        guesses.add(m)

    http_probes = []
    # decide which ports to try for HTTP(S)
    http_ports = {80, 8080, 8000, 8888}
    https_ports = {443, 8443}
    # If port_scan_results provided, restrict to open ports found
    open_ports = {e["port"] for e in port_scan_results or [] if e.get("open")}
    # Try HTTP on detected open HTTP ports, else try default host root
    ports_to_try_http = (open_ports & http_ports) or set()
    ports_to_try_https = (open_ports & https_ports) or set()

    # If no explicit open HTTP(S) ports discovered, still try basic HTTP and HTTPS root
    if not ports_to_try_http and not ports_to_try_https:
        # probe both plain http and https
        probes = []
        probes.append(probe_http(host, use_https=False, timeout=timeout))
        probes.append(probe_http(host, use_https=True, timeout=timeout))
        for p in probes:
            http_probes.append(p)
            found = analyze_http_response(p)
            for f in found:
                guesses.add(f)
    else:
        # for each open HTTP port, probe using the scheme best matching
        for p in sorted(ports_to_try_http):
            # try plain HTTP on that port
            url_host = f"{host}:{p}" if p not in (80,) else host
            pinfo = probe_http(url_host, use_https=False, timeout=timeout)
            http_probes.append(pinfo)
            for f in analyze_http_response(pinfo):
                guesses.add(f)
        for p in sorted(ports_to_try_https):
            url_host = f"{host}:{p}" if p not in (443,) else host
            pinfo = probe_http(url_host, use_https=True, timeout=timeout)
            http_probes.append(pinfo)
            for f in analyze_http_response(pinfo):
                guesses.add(f)

    return {
        "banner_matches": sorted(banner_matches),
        "http_probes": http_probes,
        "guesses": sorted(guesses)
    }
