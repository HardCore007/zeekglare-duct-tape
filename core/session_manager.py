"""Session persistence — JSON file store under data/sessions/."""
import json, time, pathlib, re

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = _PROJECT_ROOT / "data" / "sessions"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Valid scan_id: UUID v4 OR 8-64 alphanumerics + hyphens
_SCAN_ID_RE = re.compile(r"^[a-f0-9\-]{8,64}$", re.I)


def _sanitize_id(scan_id: str) -> str:
    """Prevent path traversal by validating scan_id format."""
    if not isinstance(scan_id, str) or not _SCAN_ID_RE.match(scan_id):
        raise ValueError("Invalid session ID format")
    return scan_id


class SessionManager:
    @staticmethod
    def save(scan_id, scan_type, target, name, summary, data=None,
             user_id=None, username=None):
        scan_id = _sanitize_id(scan_id)
        session = {
            "id":         scan_id,
            "type":       scan_type,
            "target":     target,
            "name":       name,
            "created_at": time.time(),
            "summary":    summary,
            "data":       data or {},
            "user_id":    user_id,
            "username":   username or "",
        }
        with open(DATA_DIR / f"{scan_id}.json", "w") as f:
            json.dump(session, f, indent=2)
        return session

    @staticmethod
    def list_all(user_id=None, admin=False):
        """Return sessions. Admin gets all; regular users only their own."""
        sessions = []
        for f in sorted(DATA_DIR.glob("*.json"), key=lambda x: -x.stat().st_mtime):
            try:
                s = json.loads(f.read_text())
                if not admin and user_id is not None:
                    if s.get("user_id") != user_id:
                        continue
                sessions.append({k: s.get(k) for k in
                                  ["id", "type", "target", "name", "created_at",
                                   "summary", "user_id", "username"]})
            except Exception:
                pass
        return sessions

    @staticmethod
    def get(scan_id, user_id=None, admin=False):
        """Return session only if requester owns it (or is admin)."""
        scan_id = _sanitize_id(scan_id)
        f = DATA_DIR / f"{scan_id}.json"
        if not f.exists():
            return None
        s = json.loads(f.read_text())
        if not admin and user_id is not None:
            if s.get("user_id") != user_id:
                return None  # treat as not-found to avoid info leak
        return s

    @staticmethod
    def delete(scan_id, user_id=None, admin=False):
        """Delete only if owner or admin. Returns True on success."""
        scan_id = _sanitize_id(scan_id)
        f = DATA_DIR / f"{scan_id}.json"
        if not f.exists():
            return False
        s = json.loads(f.read_text())
        if not admin and user_id is not None:
            if s.get("user_id") != user_id:
                return False
        f.unlink()
        return True

    @staticmethod
    def update(scan_id, patch: dict):
        """Merge patch into an existing session (internal use, no auth check)."""
        scan_id = _sanitize_id(scan_id)
        f = DATA_DIR / f"{scan_id}.json"
        if not f.exists():
            return None
        s = json.loads(f.read_text())
        s.update(patch)
        f.write_text(json.dumps(s, indent=2))
        return s

    @staticmethod
    def rename(scan_id, name, user_id=None, admin=False):
        scan_id = _sanitize_id(scan_id)
        f = DATA_DIR / f"{scan_id}.json"
        if not f.exists():
            return False
        s = json.loads(f.read_text())
        if not admin and user_id is not None:
            if s.get("user_id") != user_id:
                return False
        s["name"] = name
        f.write_text(json.dumps(s, indent=2))
        return True
