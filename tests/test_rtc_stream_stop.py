import json
from modules.rtc_inspector import RtcLogParser


def test_stream_active_false_and_destroy_clear_active_state():
    p = RtcLogParser()
    p.feed_line("[Connection(stream)] Creating connection to 104.29.143.8:19310 with audio ssrc: 12413")
    p.feed_line("[Connection(stream)] Connected with local address 189.28.181.67:65441 and protocol: udp")
    active = {"streamParameters": [{"type": "video", "active": True, "ssrc": 12414, "rtxSsrc": 12415}]}
    inactive = {"streamParameters": [{"type": "video", "active": False, "ssrc": 12414, "rtxSsrc": 12415}]}
    p.feed_line("[Connection(stream)] updateVideoQuality: " + json.dumps(active))
    assert p.sessions["stream"].active_video_ssrcs == [12414]
    events = p.feed_line("[Connection(stream)] updateVideoQuality: " + json.dumps(inactive))
    assert p.sessions["stream"].active_video_ssrcs == []
    assert any(e["type"] == "video_deactivated" for e in events)

    p.feed_line("[Connection(stream)] updateVideoQuality: " + json.dumps(active))
    events = p.feed_line("[RTCConnection(123, stream)] Destroy RTCConnection")
    assert p.sessions["stream"].active_video_ssrcs == []
    assert any(e["type"] == "stream_session_stopped" for e in events)
