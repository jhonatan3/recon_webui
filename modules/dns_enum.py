# modules/dns_enum.py
import dns.resolver
import dns.exception
from typing import Dict, List

def _safe_resolve(name: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=5.0)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []

def enumerate_dns(domain: str) -> Dict[str, List[str]]:
    """
    Return basic DNS records for the domain as a dict.
    Keys: A, AAAA, MX, NS, TXT, CNAME
    """
    domain = domain.strip()
    records = {}
    records['A'] = _safe_resolve(domain, 'A')
    records['AAAA'] = _safe_resolve(domain, 'AAAA')
    # MX returns priority and host; keep raw text
    records['MX'] = _safe_resolve(domain, 'MX')
    records['NS'] = _safe_resolve(domain, 'NS')
    records['TXT'] = _safe_resolve(domain, 'TXT')
    records['CNAME'] = _safe_resolve(domain, 'CNAME')
    return records

