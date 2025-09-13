from flask import Blueprint, render_template, request, Response, redirect, url_for
from modules.dns_enum import enumerate_dns
from modules.whois_lookup import parse_whois
from modules.subdomain_enum import find_subdomains
from modules.port_scanner import scan_ports
from modules.tech_detect import detect_technologies
from utils.logger import get_logger
import json

bp = Blueprint('main', __name__)
logger = get_logger(__name__)

# keep last result in memory for export
last_result = None

def parse_ports_input(ports_raw: str):
    if not ports_raw:
        return None
    parts = [p.strip() for p in ports_raw.replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except Exception:
            continue
    return out if out else None

@bp.route('/', methods=['GET', 'POST'])
def index():
    global last_result
    result = None
    target = None
    if request.method == 'POST':
        target = request.form.get('target')
        do_dns = request.form.get('dns') == 'on'
        do_whois = request.form.get('whois') == 'on'
        do_subs = request.form.get('subdomains') == 'on'
        do_ports = request.form.get('portscan') == 'on'
        do_tech = request.form.get('tech') == 'on'
        ports_input = request.form.get('ports') or ""
        ports_list = parse_ports_input(ports_input)
        if target:
            result = {'message': f'Received target: {target}', 'target': target}
            if do_dns:
                logger.info("Running DNS enumeration for %s", target)
                result['dns'] = enumerate_dns(target)
            if do_whois:
                logger.info("Running WHOIS lookup for %s", target)
                result['whois'] = parse_whois(target)
            if do_subs:
                logger.info("Running subdomain discovery for %s", target)
                result['subdomains'] = find_subdomains(target)
            if do_ports:
                logger.info("Running port scan for %s (ports=%s)", target, ports_list or "defaults")
                result['ports'] = scan_ports(target, ports=ports_list)
            if do_tech:
                logger.info("Running technology detection for %s", target)
                port_results = result.get('ports')
                result['tech'] = detect_technologies(target, port_scan_results=port_results)
            last_result = result
    return render_template('index.html', target=target, result=result)

@bp.route('/download/<fmt>')
def download_report(fmt):
    global last_result
    if not last_result:
        return redirect(url_for('main.index'))

    target = last_result.get('target', 'report')
    if fmt == 'json':
        data = json.dumps(last_result, indent=2, default=str)
        return Response(data, mimetype='application/json',
                        headers={"Content-Disposition": f"attachment;filename={target}_report.json"})
    elif fmt == 'txt':
        # simple text representation
        lines = [f"Recon Report for {target}\n"]
        for k, v in last_result.items():
            if k in ('message', 'target'):
                continue
            lines.append(f"\n== {k.upper()} ==")
            lines.append(json.dumps(v, indent=2, default=str))
        data = "\n".join(lines)
        return Response(data, mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={target}_report.txt"})
    elif fmt == 'html':
        # reuse template rendering
        html = render_template('report.html', result=last_result)
        return Response(html, mimetype='text/html',
                        headers={"Content-Disposition": f"attachment;filename={target}_report.html"})
    else:
        return "Unsupported format", 400
