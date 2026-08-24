import json
from pathlib import Path

from modules.rtc_inspector import RtcInspector


def test_external_stdout_feed_generates_screen_candidate(tmp_path):
    inspector = RtcInspector(tmp_path)
    inspector.attach_external_source("process-stdout")
    lines = [
        "[Connection(default)] Creating connection to 104.29.143.238:19308 with audio ssrc: 19840\n",
        "[Connection(default)] Connected with local address 189.28.181.67:65436 and protocol: udp\n",
        "[startStreamWithSource] Starting stream for source id screen-handle:65537 and name Tela 1\n",
        "[Connection(stream)] Creating connection to 104.29.142.205:19310 with audio ssrc: 20570\n",
        "[Connection(stream)] Connected with local address 189.28.181.67:65376 and protocol: udp\n",
        "[Connection(stream)] capturing desktop (type: screen-handle, handle: 65537).\n",
        '[Connection(stream)] updateVideoQuality: {"streamParameters":[{"type":"video","active":true,"rid":"100","ssrc":20571,"rtxSsrc":20572,"quality":100,"maxBitrate":9000000,"maxFrameRate":60,"maxResolution":{"type":"fixed","width":1920,"height":1080}}]}\n',
    ]
    for line in lines:
        inspector.feed_external_line(line)

    report = json.loads((tmp_path / "rtc_session.json").read_text(encoding="utf-8"))
    candidate = json.loads((tmp_path / "rtc_split_candidate.json").read_text(encoding="utf-8"))
    assert report["source_log"] == "process-stdout"
    assert report["sessions"]["default"]["remote_endpoint"] == "104.29.143.238:19308"
    assert report["sessions"]["stream"]["remote_endpoint"] == "104.29.142.205:19310"
    assert candidate["remote_ip"] == "104.29.142.205"
    assert candidate["remote_port"] == 19310
    assert candidate["local_port"] == 65376
    assert candidate["active_video_ssrcs"] == [20571]
    assert candidate["rtx_ssrcs"] == [20572]
