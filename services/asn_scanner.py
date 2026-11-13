"""StreamingMapper — ASN scanner that emits SSE events."""
import sys, os, io, contextlib, uuid, queue
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from asset_mapper import AssetMapper
from core.constants import CAT_COLORS
from core.session_manager import SessionManager


class StreamingMapper(AssetMapper):
    """AssetMapper subclass that emits SSE events instead of printing."""

    def __init__(self, *args, event_queue=None, session_id=None, securitytrails_key=None, **kwargs):
        if securitytrails_key:
            kwargs.setdefault('securitytrails_key', securitytrails_key)
        super().__init__(*args, **kwargs)
        self._eq         = event_queue or queue.Queue()
        self._processed  = 0
        self._total      = 0
        self._session_id = session_id  # pre-created session to update when done

    def emit(self, data):
        self._eq.put(data)

    def log(self, msg, level="info"):
        pass  # suppress all console output

    def get_country_asns(self):
        asns = super().get_country_asns()
        self._total = len(asns)
        self.emit({"type": "asns_found", "total": self._total})
        return asns

    def process_asn(self, asn):
        result      = super().process_asn(asn)
        self._processed += 1
        name        = result.get("name", f"AS{asn}")
        desc        = result.get("description", "")
        category    = result.get("asn_category", "commercial")
        is_critical = category != "commercial"
        color       = CAT_COLORS.get(category, CAT_COLORS["commercial"])
        classified  = result.get("classified", {})
        critical_domains = {k: v for k, v in classified.items() if v}

        self.emit({
            "type":     "asn_result",
            "progress": self._processed,
            "total":    self._total,
            "asn": {
                "asn":           asn,
                "name":          name,
                "description":   desc,
                "category":      category,
                "rir":           result.get("rir", ""),
                "country":       result.get("country", self.cc),
                "website":       result.get("website", ""),
                "prefix_count":  result.get("prefix_count", 0),
                "prefixes_v4":   result.get("prefixes_v4", []),
                "domain_count":  result.get("domain_count", 0),
                "domains":       result.get("domains", [])[:500],
                "critical":      critical_domains,
                "is_critical":   is_critical,
                "color":         color,
                "caida_rank":    result.get("caida_rank"),
                "caida_org":     result.get("caida_org", ""),
                "caida_cone_asns": result.get("caida_cone_asns", 0),
                "caida_cone_pfx":  result.get("caida_cone_pfx", 0),
            },
        })
        return result

    def generate_report(self, asn_data):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                super().generate_report(asn_data)
            except Exception:
                pass

        total_asns    = len(asn_data)
        critical_asns = sum(1 for a in asn_data if a.get("asn_category") != "commercial")
        total_domains = sum(a.get("domain_count", 0) for a in asn_data)

        self.emit({
            "type": "scan_complete",
            "summary": {
                "total_asns":    total_asns,
                "critical_asns": critical_asns,
                "total_domains": total_domains,
            },
        })

    def run(self):
        self.emit({"type": "scan_start", "country": self.cc})
        asn_data = []
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                asns = self.get_country_asns()
                if not asns:
                    self.emit({"type": "error", "message": "No ASNs found for country code."})
                    self._eq.put(None)
                    return []

                for asn in asns:
                    try:
                        asn_data.append(self.process_asn(asn))
                    except Exception:
                        pass

                self.generate_report(asn_data)
            except Exception as e:
                self.emit({"type": "error", "message": str(e)})

        # Update (or create) session with final results
        try:
            session_id    = self._session_id or str(uuid.uuid4())
            total_asns    = len(asn_data)
            critical_asns = sum(1 for a in asn_data if a.get("asn_category") != "commercial")
            total_domains = sum(a.get("domain_count", 0) for a in asn_data)
            trimmed = []
            for a in asn_data:
                entry = dict(a)
                entry["domains"] = a.get("domains", [])[:30]
                trimmed.append(entry)
            patch = {
                "summary": {
                    "status":        "done",
                    "total_asns":    total_asns,
                    "critical_asns": critical_asns,
                    "total_domains": total_domains,
                },
                "data": {"asn_data": trimmed},
            }
            if SessionManager.update(session_id, patch) is None:
                # Session wasn't pre-created — save fresh
                SessionManager.save(
                    scan_id   = session_id,
                    scan_type = "asn",
                    target    = self.cc,
                    name      = f"{self.cc} ASN Map — {datetime.now():%Y-%m-%d %H:%M}",
                    summary   = patch["summary"],
                    data      = patch["data"],
                )
            self.emit({"type": "session_saved", "scan_id": session_id})
        except Exception:
            pass

        self._eq.put(None)
        return asn_data
