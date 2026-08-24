import json
from modules.rtc_inspector import RtcLogParser


def _video_line(active: bool):
    payload = {
        "encodingVideoWidth": 1280,
        "streamParameters": [
            {"type":"video","active":active,"rid":"50","ssrc":11060,"rtxSsrc":11061,"quality":50,"maxBitrate":2500000,"maxResolution":{"type":"fixed","width":1280,"height":720}},
            {"type":"video","active":False,"rid":"100","ssrc":11062,"rtxSsrc":11063,"quality":100,"maxBitrate":2500000,"maxResolution":{"type":"fixed","width":1280,"height":720}},
        ],
    }
    return "01:24:54 > [Connection(default)] updateVideoQuality: " + json.dumps(payload)


def test_parses_endpoint_audio_and_udp_transport():
    p = RtcLogParser()
    events = p.feed_line("01:24:54 > [Connection(default)] Creating connection to 104.29.142.239:19334 with audio ssrc: 11059")
    assert p.session.remote_endpoint == "104.29.142.239:19334"
    assert p.session.audio_ssrc == 11059
    assert any(e["type"] == "media_endpoint" for e in events)

    p.feed_line("01:24:54 > [Connection(default)] Connected with local address 189.28.181.67:65497 and protocol: udp")
    assert p.session.local_endpoint == "189.28.181.67:65497"
    assert p.session.protocol == "udp"


def test_video_activation_is_detected_as_candidate_transition():
    p = RtcLogParser()
    p.feed_line(_video_line(False))
    assert p.session.all_video_ssrcs == [11060, 11062]
    assert p.session.active_video_ssrcs == []

    events = p.feed_line(_video_line(True))
    activated = [e for e in events if e["type"] == "video_activated"]
    assert len(activated) == 1
    assert activated[0]["ssrc"] == 11060
    assert activated[0]["rtx_ssrc"] == 11061
    assert p.session.active_video_ssrcs == [11060]


def test_screen_share_uses_separate_session_and_keeps_default_voice():
    p = RtcLogParser()
    p.feed_line("16:38:12 > [Connection(default)] Creating connection to 104.29.142.187:19332 with audio ssrc: 11642")
    p.feed_line("16:38:12 > [Connection(default)] Connected with local address 189.28.181.67:65199 and protocol: udp")

    p.feed_line("16:38:28 > [Connection(stream)] Creating connection to 104.29.142.175:19337 with audio ssrc: 11598")
    p.feed_line("16:38:28 > [Connection(stream)] Connected with local address 189.28.181.67:65399 and protocol: udp")
    p.feed_line("16:38:28 > [Connection(stream)] capturing desktop (type: screen-handle, handle: 65537).")
    payload = {
        "streamParameters": [
            {"type":"video","active":True,"rid":"100","ssrc":11599,"rtxSsrc":11600,"quality":100,"maxBitrate":9000000,"maxFrameRate":60,"maxResolution":{"type":"fixed","width":1920,"height":1080}}
        ]
    }
    events = p.feed_line("16:38:28 > [Connection(stream)] updateVideoQuality: " + json.dumps(payload))

    default = p.sessions["default"]
    stream = p.sessions["stream"]
    assert default.remote_endpoint == "104.29.142.187:19332"
    assert default.local_endpoint == "189.28.181.67:65199"
    assert default.audio_ssrc == 11642
    assert stream.remote_endpoint == "104.29.142.175:19337"
    assert stream.local_endpoint == "189.28.181.67:65399"
    assert stream.audio_ssrc == 11598
    assert stream.active_video_ssrcs == [11599]
    assert stream.rtx_ssrcs == [11600]
    assert stream.desktop_capture_seen is True
    assert any(e["type"] == "screen_share_candidate" for e in events)
