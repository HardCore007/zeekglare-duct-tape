"""ReconFTW runner — subprocess wrapper with SSE streaming."""
import os, subprocess, pathlib, uuid, queue, shutil
from core.constants import RECONFTW_PATHS
from core.session_manager import SessionManager

# Add user home paths dynamically
_home = os.path.expanduser("~")
SEARCH_PATHS = RECONFTW_PATHS + [
    f"{_home}/reconftw/reconftw.sh",
    shutil.which("reconftw") or "",
    shutil.which("reconftw.sh") or "",
]


def find_reconftw():
    for p in SEARCH_PATHS:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def harvest_results(out_dir: pathlib.Path, domain: str) -> dict:
    results = {"subdomains": [], "urls": [], "vulnerabilities": [], "ips": [], "screenshots": []}
    sub_files  = ["subdomains.txt", "subdomains_resolved.txt", "all_subdomains.txt",
                  f"{domain}_subdomains.txt", "results/subdomains.txt"]
    url_files  = ["urls.txt", "gau.txt", "waybackurls.txt", "results/urls.txt"]
    vuln_files = ["nuclei.txt", "vulnerabilities.txt", "results/nuclei.txt",
                  "results/vulnerabilities.txt", "xss.txt", "sqli.txt"]
    ip_files   = ["ips.txt", "alive_ips.txt", "results/ips.txt"]

    for fname in sub_files:
        fp = out_dir / fname
        if fp.is_file():
            try:
                results["subdomains"] = [l.strip() for l in fp.read_text().splitlines() if l.strip()][:2000]
                break
            except Exception:
                pass

    for fname in url_files:
        fp = out_dir / fname
        if fp.is_file():
            try:
                results["urls"] = [l.strip() for l in fp.read_text().splitlines() if l.strip()][:1000]
                break
            except Exception:
                pass

    for fname in vuln_files:
        fp = out_dir / fname
        if fp.is_file():
            try:
                results["vulnerabilities"] += [l.strip() for l in fp.read_text().splitlines() if l.strip()]
            except Exception:
                pass

    for fname in ip_files:
        fp = out_dir / fname
        if fp.is_file():
            try:
                results["ips"] = [l.strip() for l in fp.read_text().splitlines() if l.strip()][:500]
                break
            except Exception:
                pass

    for ss_dir in ("screenshots", "aquatone", "results/screenshots"):
        sp = out_dir / ss_dir
        if sp.is_dir():
            results["screenshots"] = [f.name for f in sp.iterdir()
                                       if f.suffix.lower() in (".png", ".jpg")][:50]
            break

    results["vulnerabilities"] = results["vulnerabilities"][:500]
    return results


def run_recon(scan_id, domain, mode, flags, out_dir, event_queue, scans_dict, lock,
              user_id=None, username=None):
    path    = find_reconftw()
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not path:
        event_queue.put({"type": "recon_error", "error": "reconftw not found. Please install it."})
        event_queue.put(None)
        with lock:
            if scan_id in scans_dict:
                scans_dict[scan_id]["done"] = True
        return

    cmd = ["bash", path, "-d", domain, mode, "--output", str(out_dir)]
    for f in flags:
        if isinstance(f, str) and f.startswith("-"):
            cmd.append(f)

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=str(pathlib.Path(path).parent),
        )
        with lock:
            scans_dict[scan_id]["pid"] = proc.pid

        event_queue.put({"type": "recon_start", "scan_id": scan_id,
                         "domain": domain, "mode": mode, "cmd": " ".join(cmd)})

        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip()
            if not line:
                continue
            low = line.lower()
            tag = ("finding"  if "subdomain" in low or "found" in low else
                   "error"    if "error" in low or "failed" in low else
                   "progress" if any(w in low for w in ("starting","running","checking")) else
                   "warning"  if "warn" in low else
                   "vuln"     if any(w in low for w in ("vulnerability","xss","sqli","vuln")) else
                   "success"  if any(w in low for w in ("complete","finished","done")) else
                   "info")
            event_queue.put({"type": "recon_line", "line": line, "tag": tag})

        proc.wait()
        results = harvest_results(out_dir, domain)
        event_queue.put({"type": "recon_complete", "scan_id": scan_id,
                         "return_code": proc.returncode,
                         "output_dir": str(out_dir), "results": results})

        SessionManager.save(
            scan_id=scan_id, scan_type="recon", target=domain,
            name=f"ReconFTW — {domain}",
            summary={"mode": mode, "return_code": proc.returncode, "output_dir": str(out_dir)},
            data=results,
            user_id=user_id,
            username=username,
        )
        event_queue.put({"type": "session_saved", "scan_id": scan_id})

    except Exception as e:
        event_queue.put({"type": "recon_error", "error": str(e)})
    finally:
        event_queue.put(None)
        with lock:
            if scan_id in scans_dict:
                scans_dict[scan_id]["done"] = True
