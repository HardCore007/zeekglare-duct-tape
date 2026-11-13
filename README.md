# ZeekGlare 🔦 Some Assembly Required

> A recon workbench held together by Flask, subprocesses, and a suspicious amount of duct tape.

ZeekGlare pulls DNS and subdomain discovery, port checks, web recon, and CVE lookups into one dashboard. I built it to stop bouncing between terminal tabs and keep results from the same assessment together. It's a hobby project, and some of the wiring is still hanging out. 🛠️

## What's on the bench?

- **Recon:** DNS records, domain and IP mapping, port checks, and web discovery.
- **Tool adapters:** Flask endpoints for command-line tools such as `subfinder`, `httpx`, `katana`, `nmap`, and `ffuf`. Install the tools for the features you want to try.
- **Session notes:** Save runs, compare results, and export findings as JSON, CSV, HTML, or PDF.
- **Experiments:** Separate tool dashboards, scheduled scans, and optional AI and notification integrations. These need additional configuration and are still rough around the edges.

## Try the main dashboard locally

Use Python 3.12+ and run these commands from the repo root. The bootstrap password is used only when the auth database has no users.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
read -rs ZEEKGLARE_ADMIN_PASSWORD
export ZEEKGLARE_ADMIN_PASSWORD
python -m flask --app app run --host 127.0.0.1 --cert=adhoc
```

At the `read` command, enter a password of at least 16 characters and press Enter. Open `https://127.0.0.1:5000` and sign in as `admin`. The development certificate is self-signed. Use a trusted local certificate if your browser requires one.

The published snapshot contains the application source. Tool integrations that expect local checkouts or service credentials need to be configured separately. Run scans only against systems you own or have permission to test.

## Where things live

| Path | Contents |
| --- | --- |
| `app.py`, `blueprints/` | Main dashboard and Flask routes |
| `services/`, `core/` | Recon adapters, sessions, and authentication |
| `templates/`, `static/` | Dashboard UI |
| `xploiter_app.py`, `misc_dashboard/` | Experimental companion dashboards |

Third-party attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
