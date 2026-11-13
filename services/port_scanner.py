"""Port Scanner — multi-tool, multi-target port scanning service.

Tools: nmap, masscan, RustScan, naabu
"""
import json, os, queue, re, shutil, socket, subprocess, threading, time, xml.etree.ElementTree as ET

# ── Tool detection ────────────────────────────────────────────────────────────
_NMAP     = shutil.which("nmap")
_MASSCAN  = shutil.which("masscan")
_RUSTSCAN = shutil.which("rustscan")
_NAABU    = shutil.which("naabu")

COMMON_PORTS = "21,22,23,25,53,80,110,143,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"

PORT_PROFILES = {
    "top100":   {"label": "Top 100",        "arg": "-F"},
    "top1000":  {"label": "Top 1000",       "arg": "--top-ports 1000"},
    "common":   {"label": "Common Services","arg": f"-p {COMMON_PORTS}"},
    "full":     {"label": "Full Range",     "arg": "-p 1-65535"},
    "custom":   {"label": "Custom",         "arg": None},
}

SERVICE_RISK = {
    "telnet":        "critical",
    "ftp":           "high",
    "smb":           "high", "microsoft-ds": "high", "netbios-ssn": "high",
    "rdp":           "high", "ms-wbt-server": "high",
    "vnc":           "high",
    "mysql":         "high",
    "mssql":         "high", "ms-sql-s": "high",
    "postgresql":    "high",
    "mongodb":       "high",
    "redis":         "high",
    "elasticsearch": "high",
    "ldap":          "medium",
    "snmp":          "medium",
    "smtp":          "low",
    "ssh":           "low",
    "http":          "low",
    "https":         "low",
    "dns":           "low",
}

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')


def tool_status():
    return {
        "nmap":     bool(_NMAP),
        "masscan":  bool(_MASSCAN),
        "rustscan": bool(_RUSTSCAN),
        "naabu":    bool(_NAABU),
    }


def _risk(service_name):
    return SERVICE_RISK.get((service_name or "").lower(), "info")


# ── XML parser for nmap ───────────────────────────────────────────────────────
def _parse_nmap_xml(xml_text):
    ports = []
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc  = port_el.find("service")
                scr  = port_el.find("script[@id='banner']")
                htl  = port_el.find("script[@id='http-title']")
                ssl  = port_el.find("script[@id='ssl-cert']")
                sname   = svc.get("name", "")   if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                banner  = scr.get("output", "")[:200] if scr is not None else ""
                title   = htl.get("output", "")[:120] if htl is not None else ""
                ssl_cn  = ""
                if ssl is not None:
                    m = re.search(r'commonName=([^\s/]+)', ssl.get("output", ""))
                    if m:
                        ssl_cn = m.group(1)
                ports.append({
                    "port":    int(port_el.get("portid", 0)),
                    "proto":   port_el.get("protocol", "tcp"),
                    "service": sname,
                    "product": product,
                    "version": version,
                    "banner":  banner or title,
                    "ssl_cn":  ssl_cn,
                    "risk":    _risk(sname),
                })
    except Exception:
        pass
    return ports


# ── PortScanner class ─────────────────────────────────────────────────────────
class PortScanner:
    def __init__(self, targets, tool="nmap", port_profile="common",
                 custom_ports=None, scan_type="service",
                 concurrency=2, event_queue=None):
        self.targets      = list(targets)
        self.tool         = tool
        self.port_profile = port_profile
        self.custom_ports = custom_ports or COMMON_PORTS
        self.scan_type    = scan_type    # "service" | "quick" | "aggressive"
        self.concurrency  = max(1, min(concurrency, 5))
        self._eq          = event_queue or queue.Queue()
        self._stop        = threading.Event()

    def emit(self, data):
        self._eq.put(data)

    def _port_arg(self):
        if self.port_profile == "custom":
            return f"-p {self.custom_ports}"
        prof = PORT_PROFILES.get(self.port_profile, PORT_PROFILES["common"])
        return prof["arg"]

    # ── nmap ──────────────────────────────────────────────────────────────────
    def _scan_nmap(self, target, ip):
        if not _NMAP:
            return []
        port_arg = self._port_arg()

        if self.scan_type == "quick":
            flags = ["-T4", "--open", "--max-retries", "1", "--host-timeout", "60s"]
            scripts = []
        elif self.scan_type == "aggressive":
            flags = ["-T4", "--open", "-sV", "-O", "--max-retries", "2", "--host-timeout", "120s"]
            scripts = ["--script", "banner,http-title,ssl-cert,vuln"]
        else:  # service (default)
            flags = ["-T4", "--open", "-sV", "--max-retries", "1", "--host-timeout", "90s"]
            scripts = ["--script", "banner,http-title,ssl-cert"]

        cmd = ["nmap"] + flags + port_arg.split() + scripts + ["-oX", "-", ip]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            while proc.poll() is None:
                if self._stop.is_set():
                    proc.terminate()
                    return []
                time.sleep(0.3)
            stdout, _ = proc.communicate()
            ports = _parse_nmap_xml(stdout)
            for p in ports:
                self.emit({"type": "port_result", "host": target, "ip": ip, **p})
            return ports
        except Exception:
            return []

    # ── masscan ───────────────────────────────────────────────────────────────
    def _scan_masscan(self, target, ip):
        if not _MASSCAN:
            return []
        # Determine port range for masscan
        if self.port_profile == "top100":
            ports = COMMON_PORTS  # masscan doesn't support -F
        elif self.port_profile in ("top1000", "full"):
            ports = "1-65535" if self.port_profile == "full" else "1-1024,8080,8443,8888,9200,27017"
        else:
            ports = self.custom_ports if self.port_profile == "custom" else COMMON_PORTS

        cmd = ["masscan", ip, "-p", ports, "--rate", "1000", "--open",
               "--output-format", "json", "--output-filename", "-"]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            found_ports = []
            buf = ""
            for line in proc.stdout:
                if self._stop.is_set():
                    proc.terminate()
                    return []
                line = line.strip().lstrip(",").rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    rec = json.loads(line)
                    portnum = rec.get("ports", [{}])[0].get("port", 0)
                    proto   = rec.get("ports", [{}])[0].get("proto", "tcp")
                    if portnum:
                        p = {"port": portnum, "proto": proto, "service": "",
                             "product": "", "version": "", "banner": "",
                             "ssl_cn": "", "risk": "info"}
                        found_ports.append(p)
                        self.emit({"type": "port_result", "host": target, "ip": ip, **p})
                except Exception:
                    pass
            proc.wait()
            return found_ports
        except Exception:
            return []

    # ── rustscan ──────────────────────────────────────────────────────────────
    def _scan_rustscan(self, target, ip):
        if not _RUSTSCAN:
            return []
        if self.port_profile in ("full",):
            port_range = "1-65535"
        elif self.port_profile == "custom":
            port_range = self.custom_ports
        else:
            port_range = COMMON_PORTS

        # RustScan discovers ports then hands off to nmap
        cmd = ["rustscan", "-a", ip, "-p", port_range,
               "--ulimit", "5000", "--timeout", "3000",
               "--", "-sV", "--open",
               "--script", "banner,http-title,ssl-cert", "-oX", "-"]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            xml_buf = []
            in_xml = False
            for line in proc.stdout:
                if self._stop.is_set():
                    proc.terminate()
                    return []
                if "<?xml" in line or "<nmaprun" in line:
                    in_xml = True
                if in_xml:
                    xml_buf.append(line)
            proc.wait()
            ports = _parse_nmap_xml("".join(xml_buf))
            for p in ports:
                self.emit({"type": "port_result", "host": target, "ip": ip, **p})
            return ports
        except Exception:
            return []

    # ── naabu ─────────────────────────────────────────────────────────────────
    def _scan_naabu(self, target, ip):
        if not _NAABU:
            return []
        if self.port_profile == "top100":
            port_arg = ["-top-ports", "100"]
        elif self.port_profile == "top1000":
            port_arg = ["-top-ports", "1000"]
        elif self.port_profile == "full":
            port_arg = ["-p", "1-65535"]
        else:
            p = self.custom_ports if self.port_profile == "custom" else COMMON_PORTS
            port_arg = ["-p", p]

        cmd = ["naabu", "-host", ip] + port_arg + ["-json", "-silent", "-rate", "500"]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            found_ports = []
            for line in proc.stdout:
                if self._stop.is_set():
                    proc.terminate()
                    return []
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    portnum = rec.get("port", 0)
                    if portnum:
                        p = {"port": portnum, "proto": "tcp", "service": "",
                             "product": "", "version": "", "banner": "",
                             "ssl_cn": "", "risk": "info"}
                        found_ports.append(p)
                        self.emit({"type": "port_result", "host": target, "ip": ip, **p})
                except Exception:
                    pass
            proc.wait()
            return found_ports
        except Exception:
            return []

    # ── Scan one host ─────────────────────────────────────────────────────────
    def _scan_host(self, target):
        # Resolve IP
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

        self.emit({"type": "host_start", "host": target, "ip": ip})
        t0 = time.time()

        tool = self.tool
        if tool == "nmap":
            ports = self._scan_nmap(target, ip)
        elif tool == "masscan":
            ports = self._scan_masscan(target, ip)
        elif tool == "rustscan":
            ports = self._scan_rustscan(target, ip)
        elif tool == "naabu":
            ports = self._scan_naabu(target, ip)
        else:
            ports = self._scan_nmap(target, ip)

        elapsed = round(time.time() - t0, 1)
        self.emit({
            "type":    "host_done",
            "host":    target,
            "ip":      ip,
            "elapsed": elapsed,
            "total":   len(ports),
            "critical": sum(1 for p in ports if p.get("risk") == "critical"),
            "high":    sum(1 for p in ports if p.get("risk") == "high"),
        })
        return ports

    # ── Main ──────────────────────────────────────────────────────────────────
    def run(self):
        t0 = time.time()
        self.emit({
            "type":    "scan_start",
            "targets": len(self.targets),
            "tool":    self.tool,
            "profile": self.port_profile,
        })

        sem = threading.Semaphore(self.concurrency)
        threads = []
        all_ports = []
        lock = threading.Lock()

        def _worker(t):
            with sem:
                if not self._stop.is_set():
                    result = self._scan_host(t)
                    with lock:
                        all_ports.extend(result)

        for target in self.targets:
            th = threading.Thread(target=_worker, args=(target,), daemon=True)
            threads.append(th)
            th.start()

        for th in threads:
            th.join()

        self.emit({
            "type":    "scan_done",
            "total_hosts": len(self.targets),
            "total_ports": len(all_ports),
            "elapsed": round(time.time() - t0, 1),
            "critical": sum(1 for p in all_ports if p.get("risk") == "critical"),
            "high":    sum(1 for p in all_ports if p.get("risk") == "high"),
        })
        self._eq.put(None)
