import json
import time
from pathlib import Path

from modules.rtc_inspector import RtcInspector


def _wait_until(predicate, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.03)
    return False


def test_inspector_does_not_reopen_on_every_append_and_captures_stream(tmp_path: Path):
    log = tmp_path / "media.log"
    log.write_text("existing line\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    inspector = RtcInspector(runtime, log_path=log, poll_interval=0.02)
    inspector.start()
    try:
        assert _wait_until(lambda: inspector.resolved_log == log)
        lines = [
            "[Connection(stream)] Creating connection to 104.29.142.175:19337 with audio ssrc: 11598\n",
            "[Connection(stream)] Connected with local address 189.28.181.67:65399 and protocol: udp\n",
            "[Connection(stream)] capturing desktop (type: screen-handle, handle: 65537).\n",
            '[Connection(stream)] updateVideoQuality: {"streamParameters":[{"type":"video","active":true,"rid":"100","ssrc":11599,"rtxSsrc":11600,"quality":100,"maxBitrate":9000000,"maxFrameRate":60,"maxResolution":{"type":"fixed","width":1920,"height":1080}}]}\n',
        ]
        with log.open("a", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
                f.flush()
                time.sleep(0.05)
        candidate = runtime / "rtc_split_candidate.json"
        assert _wait_until(candidate.exists)
        data = json.loads(candidate.read_text(encoding="utf-8"))
        assert data["kind"] == "screen_share_separate_rtc"
        assert data["remote_endpoint"] == "104.29.142.175:19337"
        assert data["local_endpoint"] == "189.28.181.67:65399"
        assert data["active_video_ssrcs"] == [11599]
        assert data["rtx_ssrcs"] == [11600]
    finally:
        inspector.stop()
