"""Motion-event recorder: turns live camera motion into a camera_events.csv.

Run this alongside a packet capture and it builds the camera side of the
evidence while the wireless side is being recorded, so both streams cover
exactly the same period - which is what the analysis needs.

Each motion event optionally saves a JPEG snapshot into an ``exhibits``
directory, named after the event time, so a coincident pass has a picture
attached to it.

The recorder only reads. It creates one ONVIF event subscription against the
operator's own camera, which the camera expires on its own and which
:meth:`MotionRecorder.stop` removes explicitly.
"""

from __future__ import annotations

import csv
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .onvif_min import MotionEvent, OnvifClient, OnvifError, is_motion_topic
from .tapo import CameraConfig, snapshot

CSV_HEADER = ["timestamp", "plate", "make", "model", "notes"]


@dataclass
class RecorderStatus:
    running: bool = False
    events_written: int = 0
    snapshots_saved: int = 0
    last_event: str = ""
    last_error: str = ""
    started_utc: str = ""
    messages: list = field(default_factory=list)


class MotionRecorder:
    """Subscribes to camera motion events and appends them to a CSV.

    Runs on a background thread so the GUI stays responsive; ``stop`` is safe
    to call from any thread and always tears the subscription down.
    """

    def __init__(self, config: CameraConfig, csv_path: str | Path,
                 exhibits_dir: str | Path | None = None,
                 tz_name: str = "America/New_York",
                 min_gap_s: float = 5.0,
                 save_snapshots: bool = True,
                 on_event=None, on_status=None):
        self.config = config
        self.csv_path = Path(csv_path)
        self.exhibits_dir = Path(exhibits_dir) if exhibits_dir else None
        self.tz_name = tz_name
        self.min_gap_s = min_gap_s
        self.save_snapshots = save_snapshots and exhibits_dir is not None
        self.on_event = on_event
        self.on_status = on_status

        self.status = RecorderStatus()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._client: OnvifClient | None = None
        self._subscription = ""
        self._last_written: datetime | None = None

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.status = RecorderStatus(
            running=True,
            started_utc=datetime.now(tz=timezone.utc).isoformat(timespec="seconds"))
        self._ensure_csv()
        self._thread = threading.Thread(target=self._run, name="motion-recorder",
                                        daemon=True)
        self._thread.start()
        self._notify_status()

    def stop(self, timeout: float = 6.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self._teardown()
        self.status.running = False
        self._notify_status()

    # -- worker ----------------------------------------------------------

    def _run(self) -> None:
        try:
            self._client = OnvifClient(self.config.host, self.config.onvif_port,
                                       self.config.username, self.config.password,
                                       timeout=30.0)
            self._subscription = self._client.create_pull_point("PT120S")
            self._message("Subscribed to camera motion events.")
        except OnvifError as exc:
            self.status.last_error = str(exc)
            self.status.running = False
            self._message(f"Could not subscribe: {exc}")
            self._notify_status()
            return

        renew_countdown = 0
        while not self._stop.is_set():
            try:
                events = self._client.pull_messages(self._subscription,
                                                    timeout="PT20S", limit=50)
            except OnvifError as exc:
                self.status.last_error = str(exc)
                self._message(f"Pull failed ({exc}); re-subscribing.")
                if not self._resubscribe():
                    break
                continue

            for event in events:
                if self._stop.is_set():
                    break
                if not is_motion_topic(event.raw) or not event.active:
                    continue
                self._record(event)

            renew_countdown += 1
            if renew_countdown >= 3:
                renew_countdown = 0
                try:
                    self._client.renew(self._subscription, "PT120S")
                except OnvifError:
                    self._resubscribe()

        self._teardown()

    def _resubscribe(self) -> bool:
        self._teardown()
        try:
            self._client = OnvifClient(self.config.host, self.config.onvif_port,
                                       self.config.username, self.config.password,
                                       timeout=30.0)
            self._subscription = self._client.create_pull_point("PT120S")
            return True
        except OnvifError as exc:
            self.status.last_error = str(exc)
            self.status.running = False
            self._message(f"Re-subscription failed: {exc}")
            self._notify_status()
            return False

    def _teardown(self) -> None:
        if self._client and self._subscription:
            self._client.unsubscribe(self._subscription)
        self._subscription = ""

    # -- output ----------------------------------------------------------

    def _record(self, event: MotionEvent) -> None:
        if self._last_written is not None:
            gap = (event.utc - self._last_written).total_seconds()
            if 0 <= gap < self.min_gap_s:
                return  # one vehicle triggers a run of motion messages

        local = _to_local(event.utc, self.tz_name)
        note = f"ONVIF motion event: {event.topic}"
        if event.source:
            note += f" (source {event.source})"

        snapshot_path = ""
        if self.save_snapshots:
            snapshot_path = self._save_snapshot(local)
            if snapshot_path:
                note += f" [snapshot: {Path(snapshot_path).name}]"

        with open(self.csv_path, "a", encoding="utf-8", newline="") as fh:
            csv.writer(fh).writerow([local.isoformat(timespec="milliseconds"),
                                     "", "", "", note])

        self._last_written = event.utc
        self.status.events_written += 1
        self.status.last_event = local.isoformat(timespec="seconds")
        self._notify_status()
        if self.on_event:
            try:
                self.on_event(local, note, snapshot_path)
            except Exception:
                pass

    def _save_snapshot(self, local_time) -> str:
        stamp = local_time.strftime("%Y%m%d_%H%M%S")
        target = self.exhibits_dir / f"motion_{stamp}.jpg"
        try:
            snapshot(self.config, target)
            self.status.snapshots_saved += 1
            return str(target)
        except Exception as exc:
            self.status.last_error = f"snapshot failed: {exc}"
            return ""

    def _ensure_csv(self) -> None:
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        if self.exhibits_dir:
            self.exhibits_dir.mkdir(parents=True, exist_ok=True)
        if not self.csv_path.exists() or self.csv_path.stat().st_size == 0:
            with open(self.csv_path, "w", encoding="utf-8", newline="") as fh:
                csv.writer(fh).writerow(CSV_HEADER)

    def _message(self, text: str) -> None:
        stamp = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
        self.status.messages.append(f"{stamp}Z {text}")
        self.status.messages = self.status.messages[-200:]

    def _notify_status(self) -> None:
        if self.on_status:
            try:
                self.on_status(self.status)
            except Exception:
                pass


def _to_local(utc: datetime, tz_name: str):
    from zoneinfo import ZoneInfo
    try:
        return utc.astimezone(ZoneInfo(tz_name))
    except Exception:
        return utc
