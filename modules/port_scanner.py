# modules/port_scanner.py
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import time

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443, 445, 465, 587, 636,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080
]

def _probe_banner(host: str, port: int, sock: socket.socket, timeout: float = 2.0) -> str:
    """
    Try a few polite probes to elicit a banner. Keep probes minimal to avoid causing issues.
    Returns a decoded banner string (trimmed) or empty string.
    """
    banner = b""
    try:
        # For common HTTP ports, send a simple HTTP HEAD/GET
        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            time.sleep(0.15)
            banner = sock.recv(4096)
        elif port in (443, 8443):
            # For TLS, wrap socket then send HEAD
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                try:
                    ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    time.sleep(0.15)
                    banner = ssock.recv(4096)
                except Exception:
                    # if we can't send/recv, try to get peer cert instead
                    try:
                        cert = ssock.getpeercert()
                        banner = str(cert).encode()
                    except Exception:
                        banner = b""
        else:
            # Generic: try to recv whatever the service provides
            try:
                sock.settimeout(timeout)
                banner = sock.recv(4096)
            except Exception:
                banner = b""
    except Exception:
        banner = b""
    try:
        return banner.decode(errors="ignore").strip()
    except Exception:
        return ""

def _scan_port(host: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Attempt to connect to host:port. If open, try to grab a banner.
    Returns a dict with 'port', 'open' (bool), 'banner' (str).
    """
    result = {"port": port, "open": False, "banner": ""}
    try:
        # IPv4/IPv6 handling: prefer IPv4; getaddrinfo returns tuples we can use
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addrinfo:
            return result
        family, socktype, proto, canonname, sockaddr = addrinfo[0]
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        try:
            s.connect(sockaddr)
            result["open"] = True
            # try banner
            banner = _probe_banner(host, port, s, timeout=timeout)
            result["banner"] = banner
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        # closed or filtered
        pass
    return result

def scan_ports(host: str, ports: List[int] = None, timeout: float = 1.5, max_workers: int = 30) -> List[Dict[str, Any]]:
    """
    Concurrently scan the given ports on host. Returns list of results sorted by port number.
    - host: domain or IP
    - ports: list of integers; if None, uses DEFAULT_PORTS
    - timeout: socket connect timeout in seconds
    - max_workers: ThreadPoolExecutor max workers
    """
    if ports is None:
        ports = DEFAULT_PORTS
    # Clean ports (unique, ints)
    ports = sorted({int(p) for p in ports if isinstance(p, (int, str)) and str(p).isdigit()})
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as ex:
        futures = {ex.submit(_scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results.append(r)
            except Exception:
                results.append({"port": futures[fut], "open": False, "banner": ""})
    # sort by port
    results = sorted(results, key=lambda x: x["port"])
    return results
