# cli.py
import argparse
from modules.dns_enum import enumerate_dns
from modules.whois_lookup import parse_whois
from modules.subdomain_enum import find_subdomains
from modules.port_scanner import scan_ports
from modules.tech_detect import detect_technologies
from utils.logger import get_logger
import json

logger = get_logger(__name__)

def parse_ports_arg(value: str):
    if not value:
        return None
    parts = [p.strip() for p in value.replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except Exception:
            pass
    return out if out else None

def main():
    parser = argparse.ArgumentParser(description='Recon-WebUI CLI')
    parser.add_argument('target', help='Target domain or IP')
    parser.add_argument('--dns', action='store_true', help='Run DNS enumeration')
    parser.add_argument('--whois', action='store_true', help='Run WHOIS lookup')
    parser.add_argument('--subdomains', action='store_true', help='Run crt.sh passive subdomain discovery')
    parser.add_argument('--portscan', action='store_true', help='Run TCP port scan (default common ports)')
    parser.add_argument('--ports', help='Comma-separated ports to scan (e.g. "22,80,443")')
    parser.add_argument('--tech', action='store_true', help='Run technology detection (uses banners and HTTP probes)')
    args = parser.parse_args()

    print(f"CLI received target: {args.target}")
    port_results = None
    if args.dns:
        logger.info("Running DNS enumeration for %s", args.target)
        dns_res = enumerate_dns(args.target)
        print("DNS records (JSON):")
        print(json.dumps(dns_res, indent=2))
    if args.whois:
        logger.info("Running WHOIS lookup for %s", args.target)
        whois_res = parse_whois(args.target)
        print("WHOIS results (JSON):")
        print(json.dumps(whois_res, indent=2, default=str))
    if args.subdomains:
        logger.info("Running crt.sh subdomain discovery for %s", args.target)
        subs = find_subdomains(args.target)
        print("Subdomains found:")
        print("\n".join(subs) if subs else "(none)")
    if args.portscan:
        ports_list = parse_ports_arg(args.ports)
        logger.info("Running port scan for %s (ports=%s)", args.target, ports_list or "defaults")
        port_results = scan_ports(args.target, ports=ports_list)
        print("Port scan results:")
        for r in port_results:
            status = "open" if r.get("open") else "closed/filtered"
            banner = r.get("banner") or ""
            print(f"{r['port']}: {status}")
            if banner:
                print(f"  banner: {banner[:300]}")
    if args.tech:
        logger.info("Running technology detection for %s", args.target)
        tech = detect_technologies(args.target, port_scan_results=port_results)
        print("Technology detection results:")
        print(json.dumps(tech, indent=2))
