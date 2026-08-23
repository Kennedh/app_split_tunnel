"""Read-only realtime media session inspector.

The inspector tails the desktop client's media log and extracts the network
endpoint plus RTP SSRC metadata already emitted by the client.  It does not
capture, decrypt, modify or reroute packets.

Its main purpose is to answer a prerequisite for an experimental media split:
which SSRCs belong to audio and which video/RTX streams become active when the
user starts a camera or screen-share session.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("split_tunnel.rtc_inspector")

_CREATE_RE = re.compile(
    r"Creating connection to\s+(?P<remote>\S+)\s+with audio ssrc:\s*(?P<audio>\d+)",
    re.IGNORECASE,
)
_LOCAL_RE = re.compile(
    r"Connected with local address\s+(?P<local>\S+)\s+and protocol:\s*(?P<protocol>\w+)",
    re.IGNORECASE,
)
_MEDIA_RE = re.compile(r"RTC connected to media server:\s*(?P<remote>\S+)", re.IGNORECASE)
_VIDEO_MARKER = "updateVideoQuality:"


@dataclass
class VideoStream:
    ssrc: int
    rtx_ssrc: Optional[int] = None
    rid: Optional[str] = None
    quality: Optional[int] = None
    active: bool = False
    max_bitrate: Optional[int] = None
    max_width: Optional[int] = None
    max_height: Optional[int] = None
    last_seen: float = 0.0


@dataclass
class MediaSession:
    remote_endpoint: Optional[str] = None
    local_endpoint: Optional[str] = None
    protocol: Optional[str] = None
    audio_ssrc: Optional[int] = None
    video_streams: dict[int, VideoStream] = field(default_factory=dict)
    activation_events: list[dict] = field(default_factory=list)
    updated_at: float = 0.0

    @property
    def active_video_ssrcs(self) -> list[int]:
        return sorted(s.ssrc for s in self.video_streams.values() if s.active)

    @property
    def all_video_ssrcs(self) -> list[int]:
        return sorted(self.video_streams)

    @property
    def rtx_ssrcs(self) -> list[int]:
        return sorted(s.rtx_ssrc for s in self.video_streams.values() if s.rtx_ssrc is not None)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["video_streams"] = {
            str(k): asdict(v) for k, v in sorted(self.video_streams.items())
        }
        data["active_video_ssrcs"] = self.active_video_ssrcs
        data["all_video_ssrcs"] = self.all_video_ssrcs
        data["rtx_ssrcs"] = self.rtx_ssrcs
        return data


class RtcLogParser:
    def __init__(self) -> None:
        self.session = MediaSession()

    @staticmethod
    def _int(value) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def feed_line(self, line: str) -> list[dict]:
        """Parse one client log line and return noteworthy change events."""
        events: list[dict] = []
        now = time.time()

        match = _CREATE_RE.search(line)
        if match:
            remote = match.group("remote").rstrip(",")
            audio = int(match.group("audio"))
            changed = remote != self.session.remote_endpoint or audio != self.session.audio_ssrc
            if changed and self.session.audio_ssrc is not None:
                # A new audio SSRC/endpoint marks a new RTC media session. Do
                # not carry video SSRCs from the previous call into the report.
                self.session.local_endpoint = None
                self.session.protocol = None
                self.session.video_streams.clear()
                self.session.activation_events.clear()
                events.append({"type": "session_reset", "remote": remote, "audio_ssrc": audio})
            self.session.remote_endpoint = remote
            self.session.audio_ssrc = audio
            self.session.updated_at = now
            if changed:
                events.append({"type": "media_endpoint", "remote": remote, "audio_ssrc": audio})

        match = _LOCAL_RE.search(line)
        if match:
            local = match.group("local").rstrip(",")
            protocol = match.group("protocol").lower()
            changed = local != self.session.local_endpoint or protocol != self.session.protocol
            self.session.local_endpoint = local
            self.session.protocol = protocol
            self.session.updated_at = now
            if changed:
                events.append({"type": "local_transport", "local": local, "protocol": protocol})

        match = _MEDIA_RE.search(line)
        if match:
            remote = match.group("remote").rstrip(",")
            if remote != self.session.remote_endpoint:
                self.session.remote_endpoint = remote
                self.session.updated_at = now
                events.append({"type": "media_endpoint", "remote": remote, "audio_ssrc": self.session.audio_ssrc})

        marker = line.find(_VIDEO_MARKER)
        if marker >= 0:
            payload = line[marker + len(_VIDEO_MARKER):].strip()
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                streams = obj.get("streamParameters")
                if isinstance(streams, list):
                    for item in streams:
                        if not isinstance(item, dict) or item.get("type") != "video":
                            continue
                        ssrc = self._int(item.get("ssrc"))
                        if ssrc is None:
                            continue
                        previous = self.session.video_streams.get(ssrc)
                        was_active = previous.active if previous else False
                        resolution = item.get("maxResolution") or {}
                        stream = VideoStream(
                            ssrc=ssrc,
                            rtx_ssrc=self._int(item.get("rtxSsrc")),
                            rid=str(item.get("rid")) if item.get("rid") is not None else None,
                            quality=self._int(item.get("quality")),
                            active=bool(item.get("active", False)),
                            max_bitrate=self._int(item.get("maxBitrate")),
                            max_width=self._int(resolution.get("width")) if isinstance(resolution, dict) else None,
                            max_height=self._int(resolution.get("height")) if isinstance(resolution, dict) else None,
                            last_seen=now,
                        )
                        self.session.video_streams[ssrc] = stream
                        if stream.active and not was_active:
                            event = {
                                "type": "video_activated",
                                "ssrc": stream.ssrc,
                                "rtx_ssrc": stream.rtx_ssrc,
                                "rid": stream.rid,
                                "quality": stream.quality,
                                "remote": self.session.remote_endpoint,
                                "timestamp": now,
                            }
                            self.session.activation_events.append(event)
                            events.append(event)
                        elif previous is None:
                            events.append({
                                "type": "video_discovered",
                                "ssrc": stream.ssrc,
                                "rtx_ssrc": stream.rtx_ssrc,
                                "active": stream.active,
                            })
                    self.session.updated_at = now

        return events


def find_default_media_log() -> Optional[Path]:
    """Locate the newest desktop media log for supported installations."""
    roots = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.extend([
            Path(appdata) / "discord" / "logs",
            Path(appdata) / "discordptb" / "logs",
            Path(appdata) / "discordcanary" / "logs",
        ])
    candidates: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        candidates.extend(root.glob("discord_media*.log"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


class RtcInspector:
    def __init__(
        self,
        runtime_dir: Path,
        log_path: Optional[Path] = None,
        on_event: Optional[Callable[[dict, MediaSession], None]] = None,
        poll_interval: float = 0.25,
    ) -> None:
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_path
        self.on_event = on_event
        self.poll_interval = poll_interval
        self.parser = RtcLogParser()
        self.report_path = runtime_dir / "rtc_session.json"
        self.candidate_path = runtime_dir / "rtc_split_candidate.json"
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._resolved_log: Optional[Path] = None

    @property
    def resolved_log(self) -> Optional[Path]:
        return self._resolved_log

    def _save(self) -> None:
        payload = self.parser.session.to_dict()
        payload["source_log"] = str(self._resolved_log) if self._resolved_log else None
        tmp = self.report_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.report_path)

        # The candidate file intentionally contains metadata only. It is not a
        # routing rule and cannot alter traffic by itself.
        if self.parser.session.activation_events:
            candidate = {
                "remote_endpoint": self.parser.session.remote_endpoint,
                "local_endpoint": self.parser.session.local_endpoint,
                "protocol": self.parser.session.protocol,
                "audio_ssrc": self.parser.session.audio_ssrc,
                "video_ssrcs": self.parser.session.all_video_ssrcs,
                "rtx_ssrcs": self.parser.session.rtx_ssrcs,
                "active_video_ssrcs": self.parser.session.active_video_ssrcs,
                "last_activation": self.parser.session.activation_events[-1],
                "warning": (
                    "Metadata-only candidate. Audio/video can share one UDP 5-tuple; "
                    "routing selected SSRCs through a different public IP may break the RTC session."
                ),
            }
            tmp2 = self.candidate_path.with_suffix(".json.tmp")
            tmp2.write_text(json.dumps(candidate, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp2.replace(self.candidate_path)

    def _emit(self, event: dict) -> None:
        self._save()
        if self.on_event:
            try:
                self.on_event(event, self.parser.session)
            except Exception:
                logger.exception("RTC inspector event callback failed")

    def _resolve_log_wait(self) -> Optional[Path]:
        if self.log_path:
            return self.log_path if self.log_path.exists() else None
        return find_default_media_log()

    def _run(self) -> None:
        current: Optional[Path] = None
        handle = None
        last_inode_key = None
        try:
            while not self._stop.is_set():
                candidate = self._resolve_log_wait()
                if candidate is None:
                    self._stop.wait(self.poll_interval)
                    continue
                try:
                    stat = candidate.stat()
                    inode_key = (str(candidate), stat.st_mtime_ns if os.name == "nt" else stat.st_ino)
                except OSError:
                    self._stop.wait(self.poll_interval)
                    continue

                if current != candidate or handle is None or inode_key != last_inode_key:
                    if handle:
                        handle.close()
                    current = candidate
                    self._resolved_log = candidate
                    handle = candidate.open("r", encoding="utf-8", errors="replace")
                    # We only want events generated after the inspector starts.
                    handle.seek(0, os.SEEK_END)
                    last_inode_key = inode_key
                    self._emit({"type": "log_attached", "path": str(candidate)})

                line = handle.readline()
                if not line:
                    # Follow log rotation/newer media log.
                    newer = find_default_media_log() if self.log_path is None else current
                    if newer and newer != current:
                        current = None
                        continue
                    self._stop.wait(self.poll_interval)
                    continue
                for event in self.parser.feed_line(line):
                    self._emit(event)
        finally:
            if handle:
                handle.close()
            try:
                self._save()
            except Exception:
                pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="rtc-log-inspector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
