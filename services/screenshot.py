"""Screenshot service using chromium headless."""
import subprocess, tempfile, base64, os, shutil, uuid


def _writable_tmpdir(browser: str) -> str:
    """Return a directory the browser can actually write to.

    Snap chromium runs under AppArmor confinement and cannot write to /tmp —
    its --screenshot= flag reports bytes written but the file lands in the
    snap's private namespace. Use ~/snap/chromium/common/ instead.
    """
    try:
        which_path = shutil.which(browser) or ""
        real_path  = os.path.realpath(which_path) if which_path else ""
        is_snap = "/snap/" in which_path or real_path.endswith("/snap") or "/snap/" in real_path
        if is_snap:
            snap_common = os.path.expanduser("~/snap/chromium/common")
            if os.path.isdir(snap_common):
                d = os.path.join(snap_common, "zeekglare-ss")
                os.makedirs(d, exist_ok=True)
                return d
    except Exception:
        pass
    return tempfile.mkdtemp(prefix="zeekglare-ss-")


def take_screenshot(url: str, width: int = 1280, height: int = 800) -> dict:
    """Take a screenshot of a URL using chromium headless."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    browser = None
    for candidate in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(candidate):
            browser = candidate
            break

    if not browser:
        return {"error": "No headless browser found — install chromium"}

    tmpdir  = _writable_tmpdir(browser)
    outfile = os.path.join(tmpdir, f"ss_{uuid.uuid4().hex}.png")
    try:
        subprocess.run(
            [
                browser,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-software-rasterizer",
                f"--window-size={width},{height}",
                f"--screenshot={outfile}",
                url,
            ],
            timeout=25,
            capture_output=True,
        )
        if os.path.exists(outfile):
            with open(outfile, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return {"url": url, "screenshot": data, "format": "png"}
        return {"error": "Chromium ran but produced no output"}
    except subprocess.TimeoutExpired:
        return {"error": "Screenshot timed out (25s)"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            if os.path.exists(outfile):
                os.unlink(outfile)
        except Exception:
            pass


def batch_screenshots(urls: list, width: int = 1280, height: int = 800) -> list:
    """Take screenshots of multiple URLs sequentially."""
    return [{"url": u, **take_screenshot(u, width, height)} for u in urls[:10]]
