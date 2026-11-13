"""OneForAll runner — subprocess wrapper with SSE streaming."""
import os, subprocess, pathlib, json, shutil
from core.session_manager import SessionManager

SEARCH_PATHS = [
    shutil.which("oneforall") or "",
    shutil.which("python3") or "",
]

_home = os.path.expanduser("~")
_OFA_DIRS = [
    f"{_home}/OneForAll",
    f"{_home}/oneforall",
    f"{_home}/tools/OneForAll",
    "/opt/OneForAll",
    "/usr/share/OneForAll",
]


def find_oneforall():
    """Return the path to oneforall.py if found."""
    for d in _OFA_DIRS:
        p = os.path.join(d, "oneforall.py")
        if os.path.isfile(p):
            return p
    # Try PATH
    w = shutil.which("oneforall")
    if w and os.path.isfile(w):
        return w
    return None


def harvest_results(out_dir: str, domain: str) -> dict:
    """Parse OneForAll output files for results."""
    results = {"subdomains": [], "urls": [], "ips": [], "records": []}
    out_path = pathlib.Path(out_dir)

    # OneForAll outputs CSV/JSON in results/ directory
    # Check common output patterns
    for pattern in [f"{domain}.csv", f"{domain}.json", "*.csv"]:
        for fp in out_path.glob(pattern):
            if fp.suffix == ".csv":
                try:
                    lines = fp.read_text(errors="replace").splitlines()
                    if not lines:
                        continue
                    header = lines[0].lower()
                    for line in lines[1:]:
                        parts = line.split(",")
                        if not parts:
                            continue
                        sub = parts[0].strip()
                        if sub and sub != "subdomain":
                            results["subdomains"].append(sub)
                        # Try to extract IP
                        if len(parts) > 5:
                            ip = parts[5].strip()
                            if ip and ip not in results["ips"]:
                                results["ips"].append(ip)
                except Exception:
                    pass
            elif fp.suffix == ".json":
                try:
                    data = json.loads(fp.read_text(errors="replace"))
                    if isinstance(data, list):
                        for item in data:
                            sub = item.get("subdomain") or item.get("url", "")
                            if sub:
                                results["subdomains"].append(sub)
                            ip = item.get("ip") or item.get("a", "")
                            if ip and ip not in results["ips"]:
                                results["ips"].append(ip)
                except Exception:
                    pass

    # Deduplicate
    results["subdomains"] = list(dict.fromkeys(results["subdomains"]))[:5000]
    results["ips"] = list(dict.fromkeys(results["ips"]))[:2000]
    return results


def run_oneforall(scan_id, domain, brute, dns_srv, port_scan, out_dir,
                  event_queue, scans_dict, lock,
                  user_id=None, username=None):
    """Run OneForAll in a subprocess, streaming output to event_queue."""
    script = find_oneforall()
    out_path = pathlib.Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if not script:
        event_queue.put({"type": "ofa_error", "error": "OneForAll not found. Install: git clone https://github.com/shmilylty/OneForAll && cd OneForAll && pip3 install -r requirements.txt"})
        event_queue.put(None)
        with lock:
            if scan_id in scans_dict:
                scans_dict[scan_id]["done"] = True
        return

    # Prefer venv python inside the OneForAll directory if it exists
    ofa_dir = str(pathlib.Path(script).parent)
    venv_python = os.path.join(ofa_dir, ".venv", "bin", "python3")
    if os.path.isfile(venv_python):
        python = venv_python
    else:
        python = shutil.which("python3") or "python3"
    cmd = [python, script, "--target", domain, "--path", str(out_path), "run"]

    if brute:
        cmd.insert(-1, "--brute")
        cmd.insert(-1, "True")
    if dns_srv:
        cmd.insert(-1, "--dns")
        cmd.insert(-1, "True")
    if port_scan:
        cmd.insert(-1, "--port")
        cmd.insert(-1, "small")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=str(pathlib.Path(script).parent),
        )
        with lock:
            scans_dict[scan_id]["pid"] = proc.pid

        event_queue.put({"type": "ofa_start", "scan_id": scan_id,
                         "domain": domain, "cmd": " ".join(cmd)})

        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip()
            if not line:
                continue
            low = line.lower()
            tag = ("finding"  if any(w in low for w in ("subdomain", "found", "alive")) else
                   "error"    if any(w in low for w in ("error", "failed", "exception", "traceback")) else
                   "progress" if any(w in low for w in ("starting", "running", "collecting", "brute", "request")) else
                   "warning"  if "warn" in low else
                   "success"  if any(w in low for w in ("complete", "finished", "done", "total")) else
                   "info")
            event_queue.put({"type": "ofa_line", "line": line, "tag": tag})

        proc.wait()
        results = harvest_results(str(out_path), domain)
        event_queue.put({"type": "ofa_complete", "scan_id": scan_id,
                         "return_code": proc.returncode,
                         "output_dir": str(out_path), "results": results})

        SessionManager.save(
            scan_id=scan_id, scan_type="oneforall", target=domain,
            name=f"OneForAll — {domain}",
            summary={"return_code": proc.returncode, "output_dir": str(out_path),
                      "subdomains": len(results.get("subdomains", [])),
                      "ips": len(results.get("ips", []))},
            data=results,
            user_id=user_id,
            username=username,
        )
        event_queue.put({"type": "session_saved", "scan_id": scan_id})

    except Exception as e:
        event_queue.put({"type": "ofa_error", "error": str(e)})
    finally:
        event_queue.put(None)
        with lock:
            if scan_id in scans_dict:
                scans_dict[scan_id]["done"] = True
