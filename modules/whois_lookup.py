# modules/whois_lookup.py
import whois
from typing import Dict, Any

def parse_whois(domain: str) -> Dict[str, Any]:
    """
    Perform a WHOIS lookup and return a cleaned dict of useful fields.
    """
    domain = domain.strip()
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

    # whois.whois() returns a dict-like object with many possible keys;
    # pick common ones and normalize for template-friendly display.
    result = {}
    # convert non-serializable values (e.g., datetime) to string
    for key in ("domain_name", "registrar", "whois_server", "referral_url",
                "updated_date", "creation_date", "expiration_date",
                "name_servers", "emails", "status"):
        val = getattr(w, key, None) if hasattr(w, key) else w.get(key) if isinstance(w, dict) else None
        if val is None:
            continue
        # many fields may be lists; convert to list of strings
        if isinstance(val, (list, set, tuple)):
            result[key] = [str(v) for v in val]
        else:
            result[key] = str(val)
    # include the raw text if available (small)
    raw = getattr(w, "text", None) or w.get("raw", None)
    if raw:
        result["raw"] = str(raw)[:4000]  # cap to first 4k chars for UI
    return result
