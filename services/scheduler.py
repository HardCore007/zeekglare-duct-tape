"""Scan Scheduler — APScheduler-based recurring scans."""
import threading, uuid, json, pathlib
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

_scheduler = BackgroundScheduler(daemon=True)
_scheduler.start()

SCHEDULE_FILE = pathlib.Path("data/schedules.json")
SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()


def _load() -> dict:
    if SCHEDULE_FILE.exists():
        try:
            return json.loads(SCHEDULE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save(schedules: dict):
    SCHEDULE_FILE.write_text(json.dumps(schedules, indent=2, default=str))


def list_schedules() -> list:
    return list(_load().values())


def add_schedule(scan_type: str, target: str, interval_hours: int,
                 options: dict = None) -> dict:
    """Add a recurring scan schedule."""
    sid = str(uuid.uuid4())
    schedule = {
        "id":             sid,
        "scan_type":      scan_type,
        "target":         target,
        "interval_hours": interval_hours,
        "options":        options or {},
        "created_at":     datetime.now().isoformat(),
        "last_run":       None,
        "next_run":       None,
        "run_count":      0,
        "enabled":        True,
    }

    def _job():
        """Execute the scheduled scan."""
        from services.asn_scanner  import StreamingMapper
        from services.domain_mapper import DomainMapper
        import queue as _q

        q = _q.Queue()
        try:
            if scan_type == "asn":
                mapper = StreamingMapper(
                    country_code=target,
                    threads=options.get("threads", 10),
                    event_queue=q,
                )
                mapper.run()
            elif scan_type == "domain":
                mapper = DomainMapper(
                    domain=target,
                    event_queue=q,
                    max_subs=options.get("max_subs", 100),
                )
                mapper.run()
        except Exception:
            pass

        with _lock:
            scheds = _load()
            if sid in scheds:
                scheds[sid]["last_run"] = datetime.now().isoformat()
                scheds[sid]["run_count"] += 1
                job = _scheduler.get_job(sid)
                scheds[sid]["next_run"] = str(job.next_run_time) if job else None
                _save(scheds)

    _scheduler.add_job(
        _job,
        trigger=IntervalTrigger(hours=interval_hours),
        id=sid,
        name=f"{scan_type}:{target}",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    job = _scheduler.get_job(sid)
    if job:
        schedule["next_run"] = str(job.next_run_time)

    with _lock:
        scheds = _load()
        scheds[sid] = schedule
        _save(scheds)

    return schedule


def remove_schedule(sid: str) -> bool:
    with _lock:
        scheds = _load()
        if sid not in scheds:
            return False
        del scheds[sid]
        _save(scheds)
    try:
        _scheduler.remove_job(sid)
    except Exception:
        pass
    return True


def toggle_schedule(sid: str, enabled: bool) -> bool:
    with _lock:
        scheds = _load()
        if sid not in scheds:
            return False
        scheds[sid]["enabled"] = enabled
        _save(scheds)
    try:
        if enabled:
            _scheduler.resume_job(sid)
        else:
            _scheduler.pause_job(sid)
    except Exception:
        pass
    return True


def restore_schedules():
    """Restore schedules from disk on startup."""
    scheds = _load()
    for sid, s in scheds.items():
        if not s.get("enabled"):
            continue
        try:
            _scheduler.add_job(
                lambda: None,
                trigger=IntervalTrigger(hours=s.get("interval_hours", 24)),
                id=sid,
                name=f"{s['scan_type']}:{s['target']}",
                replace_existing=True,
            )
        except Exception:
            pass


restore_schedules()
