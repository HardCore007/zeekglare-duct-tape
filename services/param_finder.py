"""ParamHawk — HTTP parameter discovery service.

Tools: Arjun (active probe), ParamSpider (archive mining), x8 (active fuzz)
"""
import json, os, queue, re, shutil, subprocess, tempfile, threading, time
from urllib.parse import urlparse

_ARJUN       = shutil.which("arjun")
_X8          = shutil.which("x8")

# ParamSpider: prefer git-cloned version in xploiter-tools, fall back to system
_TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xploiter-tools")
_PS_DIR    = os.path.join(_TOOLS_DIR, "ParamSpider")
_PS_VENV_BIN = os.path.join(_PS_DIR, ".venv", "bin")
_PS_VENV_PS  = os.path.join(_PS_VENV_BIN, "paramspider")

def _find_paramspider():
    # Git-cloned with venv — pip-installed into .venv creates the CLI entry point
    if os.path.isfile(_PS_VENV_PS):
        return _PS_VENV_PS
    # pip-installed system binary
    return shutil.which("paramspider") or ""

_PARAMSPIDER = _find_paramspider()

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')


def tool_status():
    return {
        "arjun":       bool(_ARJUN),
        "paramspider": bool(_PARAMSPIDER),  # "git" or path string — both truthy
        "x8":          bool(_X8),
    }


class ParamFinder:
    def __init__(self, targets, enabled_tools=None,
                 methods="GET", threads=10, event_queue=None):
        self.targets  = list(targets)
        self._enabled = set(enabled_tools) if enabled_tools else {"arjun", "paramspider", "x8"}
        self.methods  = methods          # "GET" | "POST" | "GET,POST"
        self.threads  = max(1, min(threads, 20))
        self._eq      = event_queue or queue.Queue()
        self._stop    = threading.Event()

    def emit(self, data):
        self._eq.put(data)

    def _on(self, tool):
        return tool in self._enabled

    # ── Tool runners ──────────────────────────────────────────────────────────

    def _run_arjun(self, url):
        if not _ARJUN:
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            outfile = f.name
        try:
            methods = self.methods.replace("GET,POST", "GET,POST,JSON")
            cmd = [_ARJUN, "-u", url, "-oJ", outfile,
                   "-m", methods, "-t", str(min(self.threads, 10)), "-q"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env={**os.environ, "TERM": "dumb"},
            )
            # Poll so we can honour stop
            while proc.poll() is None:
                if self._stop.is_set():
                    proc.terminate()
                    return []
                time.sleep(0.2)

            if not os.path.isfile(outfile):
                return []
            with open(outfile) as fh:
                raw = json.load(fh)
            results = []
            for _url, method_map in raw.items():
                for method, params in method_map.items():
                    for p in (params or []):
                        if p:
                            results.append({"param": str(p), "method": method.upper()})
            return results
        except Exception:
            return []
        finally:
            try: os.unlink(outfile)
            except: pass

    def _run_paramspider(self, url):
        if not _PARAMSPIDER:
            return []
        domain = urlparse(url).netloc or url.split("/")[0]
        if not domain:
            return []
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                outfile = os.path.join(tmpdir, "out.txt")
                cmd = [_PARAMSPIDER, "-d", domain, "-o", outfile, "--quiet"]
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, cwd=tmpdir,
                    env={**os.environ, "TERM": "dumb"},
                )
                while proc.poll() is None:
                    if self._stop.is_set():
                        proc.terminate()
                        return []
                    time.sleep(0.2)

                # Newer paramspider may write to results/ dir
                if not os.path.isfile(outfile):
                    for root, _, files in os.walk(tmpdir):
                        for fname in files:
                            if fname.endswith(".txt"):
                                outfile = os.path.join(root, fname)
                                break

                if not os.path.isfile(outfile):
                    return []

                param_re = re.compile(r'[?&]([^=&\s#"\'<>]+)=')
                seen = set()
                results = []
                with open(outfile, errors="replace") as fh:
                    for line in fh:
                        for m in param_re.findall(line.strip()):
                            if m and m not in seen:
                                seen.add(m)
                                results.append({"param": m, "method": "GET"})
                return results
        except Exception:
            return []

    def _run_x8(self, url):
        if not _X8:
            return []
        # x8 requires a wordlist — use a small built-in one if seclists not found
        wl_candidates = [
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            "/usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
        ]
        wordlist = next((w for w in wl_candidates if os.path.isfile(w)), None)
        if not wordlist:
            return []
        try:
            fuzz_url = url if "FUZZ" in url else f"{url}?FUZZ=test"
            cmd = [_X8, "-u", fuzz_url, "-w", wordlist,
                   "-t", str(min(self.threads, 5)),
                   "--disable-progress", "--output-format", "url"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env={**os.environ, "TERM": "dumb"},
            )
            lines = []
            while proc.poll() is None:
                if self._stop.is_set():
                    proc.terminate()
                    return []
                line = proc.stdout.readline()
                if line:
                    lines.append(line)
            lines += proc.stdout.readlines()

            param_re = re.compile(r'[?&]([^=&\s#"\'<>]+)=')
            seen = set()
            results = []
            for line in lines:
                line = _ANSI.sub("", line).strip()
                if not line:
                    continue
                for m in param_re.findall(line):
                    if m and m != "FUZZ" and m not in seen:
                        seen.add(m)
                        results.append({"param": m, "method": "GET"})
            return results
        except Exception:
            return []

    # ── Per-URL processor ─────────────────────────────────────────────────────

    def _process_url(self, url):
        merged = {}   # param -> {methods: set, sources: set}

        def _merge(results, source):
            for r in results:
                p = r["param"]
                if p not in merged:
                    merged[p] = {"methods": set(), "sources": set()}
                merged[p]["methods"].add(r["method"])
                merged[p]["sources"].add(source)

        if self._on("arjun") and not self._stop.is_set():
            self.emit({"type": "tool_start", "tool": "arjun", "url": url})
            res = self._run_arjun(url)
            _merge(res, "arjun")
            self.emit({"type": "tool_done", "tool": "arjun", "url": url, "found": len(res)})

        if self._on("paramspider") and not self._stop.is_set():
            self.emit({"type": "tool_start", "tool": "paramspider", "url": url})
            res = self._run_paramspider(url)
            _merge(res, "paramspider")
            self.emit({"type": "tool_done", "tool": "paramspider", "url": url, "found": len(res)})

        if self._on("x8") and not self._stop.is_set():
            self.emit({"type": "tool_start", "tool": "x8", "url": url})
            res = self._run_x8(url)
            _merge(res, "x8")
            self.emit({"type": "tool_done", "tool": "x8", "url": url, "found": len(res)})

        for param, meta in merged.items():
            self.emit({
                "type":    "param_found",
                "url":     url,
                "param":   param,
                "methods": sorted(meta["methods"]),
                "sources": sorted(meta["sources"]),
            })

        self.emit({"type": "url_done", "url": url, "total": len(merged)})
        return len(merged)

    # ── Main ─────────────────────────────────────────────────────────────────

    def run(self):
        t0 = time.time()
        self.emit({"type": "scan_start", "targets": len(self.targets)})
        total = 0
        for url in self.targets:
            if self._stop.is_set():
                break
            self.emit({"type": "url_start", "url": url})
            total += self._process_url(url)
        self.emit({"type": "scan_done", "total": total,
                   "elapsed": round(time.time() - t0, 1)})
        self._eq.put(None)
