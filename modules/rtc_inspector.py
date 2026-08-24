"""Read-only realtime RTC session inspector.

The inspector tails the desktop client's media log and extracts endpoint/SSRC
metadata already emitted by the client. It does not capture, decrypt, modify or
reroute packets.

v13 keeps separate logical sessions for Connection(default) and
Connection(stream). This matters because screen sharing can use a completely
separate UDP 5-tuple from the normal voice connection, which is a much cleaner
split boundary than individual RTP SSRCs.
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
from typing import Callable, Optional, TextIO

logger = logging.getLogger("split_tunnel.rtc_inspector")

_CREATE_RE = re.compile(
    r"\[Connection\((?P<context>[^)]+)\)\].*Creating connection to\s+"
    r"(?P<remote>\S+)\s+with audio ssrc:\s*(?P<audio>\d+)",
    re.IGNORECASE,
)
_LOCAL_RE = re.compile(
    r"\[Connection\((?P<context>[^)]+)\)\].*Connected with local address\s+"
    r"(?P<local>\S+)\s+and protocol:\s*(?P<protocol>\w+)",
    re.IGNORECASE,
)
_MEDIA_RE = re.compile(
    r"\[RTCConnection\([^,]+,\s*(?P<context>[^)]+)\)\].*RTC connected to media server:\s*(?P<remote>\S+)",
    re.IGNORECASE,
)
_VIDEO_RE = re.compile(
    r"\[Connection\((?P<context>[^)]+)\)\].*updateVideoQuality:\s*(?P<payload>\{.*\})\s*$",
    re.IGNORECASE,
)
_SCREEN_START_RE = re.compile(r"\[startStreamWithSource\]\s+Starting stream", re.IGNORECASE)
_SCREEN_CAPTURE_RE = re.compile(
    r"\[Connection\((?P<context>stream)\)\].*capturing desktop",
    re.IGNORECASE,
)

_STREAM_DESTROY_RE = re.compile(r"\[RTCConnection\([^,]+,\s*(?P<context>stream)\)\].*Destroy RTCConnection", re.IGNORECASE)


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
    max_framerate: Optional[int] = None
    last_seen: float = 0.0


@dataclass
class MediaSession:
    context: str = "default"
    remote_endpoint: Optional[str] = None
    local_endpoint: Optional[str] = None
    protocol: Optional[str] = None
    audio_ssrc: Optional[int] = None
    video_streams: dict[int, VideoStream] = field(default_factory=dict)
    activation_events: list[dict] = field(default_factory=list)
    desktop_capture_seen: bool = False
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
        self.sessions: dict[str, MediaSession] = {"default": MediaSession(context="default")}
        self.screen_share_requested_at: float = 0.0

    @property
    def session(self) -> MediaSession:
        """Backwards-compatible default session accessor used by older tests."""
        return self.sessions.setdefault("default", MediaSession(context="default"))

    def get_session(self, context: str) -> MediaSession:
        context = (context or "default").strip().lower()
        return self.sessions.setdefault(context, MediaSession(context=context))

    @staticmethod
    def _int(value) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def feed_line(self, line: str) -> list[dict]:
        events: list[dict] = []
        now = time.time()

        if _SCREEN_START_RE.search(line):
            self.screen_share_requested_at = now
            events.append({"type": "screen_share_requested", "timestamp": now})

        match = _CREATE_RE.search(line)
        if match:
            context = match.group("context").strip().lower()
            session = self.get_session(context)
            remote = match.group("remote").rstrip(",")
            audio = int(match.group("audio"))
            changed = remote != session.remote_endpoint or audio != session.audio_ssrc
            if changed and session.audio_ssrc is not None:
                session.local_endpoint = None
                session.protocol = None
                session.video_streams.clear()
                session.activation_events.clear()
                session.desktop_capture_seen = False
                events.append({"type": "session_reset", "context": context, "remote": remote, "audio_ssrc": audio})
            session.remote_endpoint = remote
            session.audio_ssrc = audio
            session.updated_at = now
            if changed:
                events.append({"type": "media_endpoint", "context": context, "remote": remote, "audio_ssrc": audio})

        match = _LOCAL_RE.search(line)
        if match:
            context = match.group("context").strip().lower()
            session = self.get_session(context)
            local = match.group("local").rstrip(",")
            protocol = match.group("protocol").lower()
            changed = local != session.local_endpoint or protocol != session.protocol
            session.local_endpoint = local
            session.protocol = protocol
            session.updated_at = now
            if changed:
                events.append({"type": "local_transport", "context": context, "local": local, "protocol": protocol})

        match = _MEDIA_RE.search(line)
        if match:
            context = match.group("context").strip().lower()
            session = self.get_session(context)
            remote = match.group("remote").rstrip(",")
            if remote != session.remote_endpoint:
                session.remote_endpoint = remote
                session.updated_at = now
                events.append({"type": "media_endpoint", "context": context, "remote": remote, "audio_ssrc": session.audio_ssrc})

        match = _SCREEN_CAPTURE_RE.search(line)
        if match:
            context = match.group("context").strip().lower()
            session = self.get_session(context)
            if not session.desktop_capture_seen:
                session.desktop_capture_seen = True
                session.updated_at = now
                events.append({
                    "type": "screen_capture_confirmed",
                    "context": context,
                    "remote": session.remote_endpoint,
                    "local": session.local_endpoint,
                    "timestamp": now,
                })

        match = _STREAM_DESTROY_RE.search(line)
        if match:
            context = match.group("context").strip().lower()
            session = self.get_session(context)
            changed = False
            for stream in session.video_streams.values():
                if stream.active:
                    stream.active = False
                    stream.last_seen = now
                    changed = True
            session.updated_at = now
            events.append({"type": "stream_session_stopped", "context": context, "timestamp": now})

        match = _VIDEO_RE.search(line)
        if match:
            context = match.group("context").strip().lower()
            session = self.get_session(context)
            payload = match.group("payload")
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
                        previous = session.video_streams.get(ssrc)
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
                            max_framerate=self._int(item.get("maxFrameRate")),
                            last_seen=now,
                        )
                        session.video_streams[ssrc] = stream
                        if stream.active and not was_active:
                            event = {
                                "type": "video_activated",
                                "context": context,
                                "ssrc": stream.ssrc,
                                "rtx_ssrc": stream.rtx_ssrc,
                                "rid": stream.rid,
                                "quality": stream.quality,
                                "remote": session.remote_endpoint,
                                "local": session.local_endpoint,
                                "timestamp": now,
                            }
                            session.activation_events.append(event)
                            events.append(event)
                            if context == "stream":
                                events.append({
                                    "type": "screen_share_candidate",
                                    "context": context,
                                    "remote": session.remote_endpoint,
                                    "local": session.local_endpoint,
                                    "protocol": session.protocol,
                                    "ssrc": stream.ssrc,
                                    "rtx_ssrc": stream.rtx_ssrc,
                                    "timestamp": now,
                                })
                        elif (not stream.active) and was_active:
                            events.append({
                                "type": "video_deactivated",
                                "context": context,
                                "ssrc": stream.ssrc,
                                "rtx_ssrc": stream.rtx_ssrc,
                                "remote": session.remote_endpoint,
                                "local": session.local_endpoint,
                                "timestamp": now,
                            })
                        elif previous is None:
                            events.append({
                                "type": "video_discovered",
                                "context": context,
                                "ssrc": stream.ssrc,
                                "rtx_ssrc": stream.rtx_ssrc,
                                "active": stream.active,
                            })
                    session.updated_at = now

        return events

    def to_dict(self) -> dict:
        return {
            "sessions": {name: session.to_dict() for name, session in sorted(self.sessions.items())},
            "screen_share_requested_at": self.screen_share_requested_at,
            "updated_at": max((s.updated_at for s in self.sessions.values()), default=0.0),
        }


def find_default_media_log() -> Optional[Path]:
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


def _open_shared_read(path: Path) -> TextIO:
    """Open a log without blocking the producer from writing/rotating it."""
    if os.name != "nt":
        return path.open("r", encoding="utf-8", errors="replace")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE

    handle = kernel32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), f"Não foi possível abrir log compartilhado: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    fd = msvcrt.open_osfhandle(int(handle), flags)
    return os.fdopen(fd, "r", encoding="utf-8", errors="replace")


class RtcInspector:
    def __init__(
        self,
        runtime_dir: Path,
        log_path: Optional[Path] = None,
        on_event: Optional[Callable[[dict, MediaSession], None]] = None,
        poll_interval: float = 0.20,
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
        self._source_description: Optional[str] = None
        self._lock = threading.RLock()

    @property
    def resolved_log(self) -> Optional[Path]:
        return self._resolved_log

    @staticmethod
    def _endpoint_parts(endpoint: Optional[str]) -> tuple[Optional[str], Optional[int]]:
        if not endpoint or ":" not in endpoint:
            return endpoint, None
        host, port = endpoint.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return endpoint, None

    def _screen_candidate(self) -> Optional[dict]:
        session = self.parser.sessions.get("stream")
        if not session:
            return None
        if not session.activation_events or not session.remote_endpoint or session.protocol != "udp":
            return None
        active = session.active_video_ssrcs
        last_activation = session.activation_events[-1]
        remote_ip, remote_port = self._endpoint_parts(session.remote_endpoint)
        local_ip, local_port = self._endpoint_parts(session.local_endpoint)
        return {
            "kind": "screen_share_separate_rtc",
            "context": "stream",
            "remote_endpoint": session.remote_endpoint,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_endpoint": session.local_endpoint,
            "local_ip": local_ip,
            "local_port": local_port,
            "protocol": session.protocol,
            "audio_ssrc": session.audio_ssrc,
            "video_ssrcs": session.all_video_ssrcs,
            "active_video_ssrcs": active,
            "rtx_ssrcs": session.rtx_ssrcs,
            "last_activation": last_activation,
            "desktop_capture_seen": session.desktop_capture_seen,
            "important": (
                "Screen-share is using its own RTC/UDP 5-tuple. A future experiment can route this "
                "whole stream endpoint separately while leaving the default voice endpoint direct."
            ),
        }

    def _save(self) -> None:
        with self._lock:
            payload = self.parser.to_dict()
            payload["source_log"] = self._source_description or (str(self._resolved_log) if self._resolved_log else None)
            candidate = self._screen_candidate()
            payload["screen_share_candidate"] = candidate

            tmp = self.report_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.report_path)

            if candidate:
                tmp2 = self.candidate_path.with_suffix(".json.tmp")
                tmp2.write_text(json.dumps(candidate, indent=2, ensure_ascii=False), encoding="utf-8")
                tmp2.replace(self.candidate_path)

    def _emit(self, event: dict) -> None:
        self._save()
        if self.on_event:
            context = event.get("context", "default")
            session = self.parser.get_session(context)
            try:
                self.on_event(event, session)
            except Exception:
                logger.exception("RTC inspector event callback failed")


    def attach_external_source(self, description: str = "process-stdout") -> None:
        """Switch the parser to lines supplied directly by the parent process."""
        with self._lock:
            self._source_description = description
            self._save()

    def feed_external_line(self, line: str) -> None:
        """Feed one stdout/stderr line emitted by the launched application.

        This is the preferred path when the app is launched by this project,
        because detailed Connection(default)/Connection(stream) diagnostics are
        written to process output even when the native media log only contains
        a couple of startup lines.
        """
        with self._lock:
            if not self._source_description:
                self._source_description = "process-stdout"
            events = self.parser.feed_line(line)
            if not events:
                return
            for event in events:
                self._emit(event)

    def _resolve_log_wait(self) -> Optional[Path]:
        if self.log_path:
            return self.log_path if self.log_path.exists() else None
        return find_default_media_log()

    def _open_and_seek_end(self, candidate: Path) -> TextIO:
        handle = _open_shared_read(candidate)
        handle.seek(0, os.SEEK_END)
        return handle

    def _run(self) -> None:
        current: Optional[Path] = None
        handle: Optional[TextIO] = None
        try:
            while not self._stop.is_set():
                candidate = self._resolve_log_wait()
                if candidate is None:
                    self._stop.wait(self.poll_interval)
                    continue

                if current != candidate or handle is None:
                    if handle:
                        handle.close()
                    try:
                        handle = self._open_and_seek_end(candidate)
                    except OSError:
                        handle = None
                        self._stop.wait(self.poll_interval)
                        continue
                    current = candidate
                    self._resolved_log = candidate
                    self._emit({"type": "log_attached", "path": str(candidate)})

                # Detect same-path truncation/rotation without reopening on every
                # write. The old implementation used mtime_ns as file identity on
                # Windows, so every appended line caused a reopen+seek(END) and
                # the inspector skipped the very lines it was supposed to parse.
                try:
                    size = candidate.stat().st_size
                    pos = handle.tell()
                    if size < pos:
                        handle.close()
                        handle = _open_shared_read(candidate)
                        current = candidate
                        self._resolved_log = candidate
                        self._emit({"type": "log_reopened", "path": str(candidate)})
                except OSError:
                    try:
                        handle.close()
                    except Exception:
                        pass
                    handle = None
                    current = None
                    self._stop.wait(self.poll_interval)
                    continue

                line = handle.readline()
                if not line:
                    newer = find_default_media_log() if self.log_path is None else current
                    if newer and newer != current:
                        handle.close()
                        handle = None
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
