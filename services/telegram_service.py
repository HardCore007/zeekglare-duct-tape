"""ZeekGlare Telegram Bot — long-polling, SSE-backed scan streaming."""
import json, logging, re, requests, threading, time

logger = logging.getLogger(__name__)
_TG = "https://api.telegram.org/bot{token}/{method}"


class TelegramBot:
    def __init__(self, token, allowed_chat_id=None, anthropic_key=None):
        self.token          = token
        self.allowed        = str(allowed_chat_id).strip() if allowed_chat_id else None
        self.anthropic_key  = anthropic_key
        self._stop          = threading.Event()
        self._offset        = 0
        self._thread        = None
        self._active        = {}   # scan_id → {type, target, chat_id}

    # ── Telegram API ──────────────────────────────────────────────────────────
    def _api(self, method, **kw):
        try:
            r = requests.post(_TG.format(token=self.token, method=method),
                              json=kw, timeout=30)
            return r.json()
        except Exception as e:
            logger.error("TG %s: %s", method, e)
            return {}

    def send(self, chat_id, text, parse_mode="Markdown"):
        for chunk in [text[i:i+4000] for i in range(0, max(len(text), 1), 4000)]:
            self._api("sendMessage", chat_id=int(chat_id), text=chunk,
                      parse_mode=parse_mode, disable_web_page_preview=True)

    def typing(self, chat_id):
        self._api("sendChatAction", chat_id=int(chat_id), action="typing")

    # ── Auth ──────────────────────────────────────────────────────────────────
    def _ok(self, chat_id):
        return not self.allowed or str(chat_id).strip() == self.allowed

    # ── Dispatch ──────────────────────────────────────────────────────────────
    def _handle(self, msg):
        cid  = msg.get("chat", {}).get("id")
        text = (msg.get("text") or "").strip()
        if not cid or not text:
            return
        if not self._ok(cid):
            self.send(cid, "⛔ Unauthorized."); return
        self.typing(cid)
        if text.startswith("/"):
            self._cmd(cid, text)
        else:
            self._ai(cid, text)

    # ── Commands ──────────────────────────────────────────────────────────────
    def _cmd(self, cid, text):
        parts = text.split(None, 1)
        cmd   = parts[0].lower().lstrip("/").split("@")[0]
        arg   = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("start", "help"):
            self.send(cid,
                "*ZeekGlare Intelligence Bot* 🕵️\n\n"
                "*Scan Commands*\n"
                "`/scan domain.com` — Domain mapper & enumeration\n"
                "`/ports host1,host2` — Multi-tool port scanner\n"
                "`/params url1,url2` — HTTP parameter discovery\n"
                "`/ip domain.com` — IP scope & ASN mapping\n\n"
                "*Status*\n"
                "`/status` — Active scans\n\n"
                "*AI Chat*\n"
                "Send any message for ZeekGlare AI analysis\n\n"
                "_All scans run on your ZeekGlare server._"
            )
        elif cmd == "scan":
            if not arg: self.send(cid, "Usage: `/scan domain.com`"); return
            self.send(cid, f"🔍 Starting domain scan for `{arg}`…")
            threading.Thread(target=self._domain_scan, args=(cid, arg), daemon=True).start()
        elif cmd == "ports":
            if not arg: self.send(cid, "Usage: `/ports host1,host2`"); return
            targets = [t.strip() for t in arg.split(",") if t.strip()]
            self.send(cid, f"🔌 Port scanning {len(targets)} target(s)…")
            threading.Thread(target=self._port_scan, args=(cid, targets), daemon=True).start()
        elif cmd == "params":
            if not arg: self.send(cid, "Usage: `/params https://url1,https://url2`"); return
            targets = [t.strip() for t in arg.split(",") if t.strip()]
            self.send(cid, f"🦅 ParamHawk on {len(targets)} URL(s)…")
            threading.Thread(target=self._param_scan, args=(cid, targets), daemon=True).start()
        elif cmd == "ip":
            if not arg: self.send(cid, "Usage: `/ip domain.com`"); return
            self.send(cid, f"🌐 IP scope scan for `{arg}`…")
            threading.Thread(target=self._ip_scan, args=(cid, arg), daemon=True).start()
        elif cmd == "status":
            if not self._active:
                self.send(cid, "No active scans running.")
            else:
                lines = ["*Active Scans:*"]
                for sid, info in self._active.items():
                    lines.append(f"• `{sid[:8]}` — {info['type']} — {info.get('target','?')}")
                self.send(cid, "\n".join(lines))
        else:
            self.send(cid, f"Unknown command `/{cmd}`. Use /help.")

    # ── Internal API calls ────────────────────────────────────────────────────
    def _post(self, path, body):
        return requests.post(f"http://localhost:5000{path}", json=body, timeout=15).json()

    def _stream(self, path):
        """Yield parsed SSE events until done/stop."""
        try:
            with requests.get(f"http://localhost:5000{path}", stream=True, timeout=900) as r:
                for line in r.iter_lines():
                    if self._stop.is_set():
                        return
                    if not line:
                        continue
                    s = line.decode("utf-8", errors="ignore")
                    if not s.startswith("data:"):
                        continue
                    try:
                        ev = json.loads(s[5:].strip())
                        if ev.get("type") in ("done", "keepalive"):
                            return
                        yield ev
                    except Exception:
                        pass
        except Exception as e:
            logger.error("Stream %s: %s", path, e)

    # ── Scan runners ──────────────────────────────────────────────────────────
    def _domain_scan(self, cid, domain):
        sid = None
        try:
            d = self._post("/api/domain-scan", {"domain": domain})
            sid = d.get("scan_id")
            if not sid:
                self.send(cid, f"❌ {d.get('error','Failed to start')}"); return
            self._active[sid] = {"type": "domain", "target": domain, "chat_id": cid}
            rows = []
            for ev in self._stream(f"/api/domain-stream/{sid}"):
                if ev.get("type") == "result":
                    live = " ✅" if ev.get("http_live") else ""
                    rows.append(f"`{ev.get('domain','')}` {ev.get('http_status','')}{live}")
            msg = f"*Domain Scan Done* ✅\n_{len(rows)} subdomains found for {domain}_\n\n"
            msg += "\n".join(rows[:40])
            if len(rows) > 40:
                msg += f"\n_…and {len(rows)-40} more_"
            self.send(cid, msg)
        except Exception as e:
            self.send(cid, f"❌ Error: {e}")
        finally:
            if sid: self._active.pop(sid, None)

    def _port_scan(self, cid, targets):
        sid = None
        try:
            d = self._post("/api/ports/scan", {
                "targets": targets, "tool": "nmap", "port_profile": "common"
            })
            sid = d.get("scan_id")
            if not sid:
                self.send(cid, f"❌ {d.get('error','Failed')}"); return
            self._active[sid] = {"type": "ports", "target": ",".join(targets[:3]), "chat_id": cid}
            findings = []
            for ev in self._stream(f"/api/ports/stream/{sid}"):
                if ev.get("type") == "port_result":
                    risk = ev.get("risk", "info")
                    icon = "🔴" if risk=="critical" else "🟠" if risk=="high" else "🟡" if risk=="medium" else "🟢"
                    findings.append(f"{icon} `{ev.get('host','')}:{ev.get('port','')}` {ev.get('service','')}")
            msg = f"*Port Scan Done* ✅\n_{len(findings)} open ports_\n\n"
            msg += "\n".join(findings[:35])
            if len(findings) > 35:
                msg += f"\n_…and {len(findings)-35} more_"
            self.send(cid, msg)
        except Exception as e:
            self.send(cid, f"❌ Error: {e}")
        finally:
            if sid: self._active.pop(sid, None)

    def _param_scan(self, cid, targets):
        sid = None
        try:
            d = self._post("/api/param/start", {"targets": targets})
            sid = d.get("scan_id")
            if not sid:
                self.send(cid, f"❌ {d.get('error','Failed')}"); return
            self._active[sid] = {"type": "params", "target": targets[0], "chat_id": cid}
            found = []
            for ev in self._stream(f"/api/param/stream/{sid}"):
                if ev.get("type") == "param_found":
                    found.append(f"`{ev.get('param','')}` — {ev.get('url','')}")
            msg = f"*ParamHawk Done* ✅\n_{len(found)} parameters discovered_\n\n"
            msg += "\n".join(found[:40])
            self.send(cid, msg)
        except Exception as e:
            self.send(cid, f"❌ Error: {e}")
        finally:
            if sid: self._active.pop(sid, None)

    def _ip_scan(self, cid, domain):
        sid = None
        try:
            d = self._post("/api/ip-map/start", {"domain": domain})
            sid = d.get("scan_id")
            if not sid:
                self.send(cid, f"❌ {d.get('error','Failed')}"); return
            self._active[sid] = {"type": "ip", "target": domain, "chat_id": cid}
            ips = []
            for ev in self._stream(f"/api/ip-map/stream/{sid}"):
                if ev.get("type") == "ip_result":
                    ips.append(f"`{ev.get('ip','')}` ASN{ev.get('asn','?')} {ev.get('country','')}")
            msg = f"*IP Scope Done* ✅\n_{len(ips)} IPs mapped for {domain}_\n\n"
            msg += "\n".join(ips[:30])
            self.send(cid, msg)
        except Exception as e:
            self.send(cid, f"❌ Error: {e}")
        finally:
            if sid: self._active.pop(sid, None)

    # ── AI forwarding ─────────────────────────────────────────────────────────
    def _ai(self, cid, text):
        if not self.anthropic_key:
            self.send(cid, "⚠️ No Anthropic key configured.\nAdd it in ZeekGlare → Settings → AI & Chat."); return
        try:
            r = requests.post("http://localhost:5000/api/chat", json={
                "provider": "anthropic",
                "model": "claude-haiku-4-5",
                "api_key": self.anthropic_key,
                "messages": [{"role": "user", "content": text}],
                "context": "",
            }, stream=True, timeout=120)
            full = ""
            for line in r.iter_lines():
                if not line: continue
                s = line.decode("utf-8", errors="ignore")
                if not s.startswith("data:"): continue
                try:
                    ev = json.loads(s[5:].strip())
                    if ev.get("type") == "text":
                        full += ev.get("text", "")
                    elif ev.get("type") in ("done", "error"):
                        break
                except Exception:
                    pass
            if full:
                full = re.sub(r'<ZG_ACTION>.*?</ZG_ACTION>', '', full, flags=re.DOTALL).strip()
                self.send(cid, full)
        except Exception as e:
            self.send(cid, f"❌ AI error: {e}")

    # ── Polling lifecycle ─────────────────────────────────────────────────────
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()
        logger.info("Telegram bot polling started (…%s)", self.token[-6:])

    def stop(self):
        self._stop.set()

    def is_running(self):
        return bool(self._thread and self._thread.is_alive())

    def _poll(self):
        while not self._stop.is_set():
            try:
                r = requests.get(
                    _TG.format(token=self.token, method="getUpdates"),
                    params={"offset": self._offset, "timeout": 30,
                            "allowed_updates": ["message"]},
                    timeout=40
                )
                data = r.json()
                if not data.get("ok"):
                    time.sleep(5); continue
                for upd in data.get("result", []):
                    self._offset = upd["update_id"] + 1
                    msg = upd.get("message")
                    if msg:
                        try:
                            self._handle(msg)
                        except Exception as e:
                            logger.error("Handle: %s", e)
            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                logger.error("Poll: %s", e)
                time.sleep(5)
