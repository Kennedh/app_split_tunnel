from modules.rtc_tunnel import RtcTunnelEngine, derive_route_cidr


def test_derive_route_cidr_defaults_to_rtc_slash16():
    assert derive_route_cidr("104.29.143.8") == "104.29.0.0/16"


def test_rtc_tun_excludes_voice_server_ip_before_packets_enter_tun():
    cfg = RtcTunnelEngine.build_config(
        udp_proxy="203.0.113.10:1080",
        target_process_name="Target.exe",
        route_cidr="104.29.0.0/16",
        voice_remote_ip="104.29.142.198",
    )
    tun = cfg["inbounds"][0]
    assert tun["type"] == "tun"
    assert tun["auto_route"] is True
    assert tun["route_address"] == ["104.29.0.0/16"]
    # Voice and the relay itself stay outside the TUN at Windows route level.
    assert "104.29.142.198/32" in tun["route_exclude_address"]
    assert "203.0.113.10/32" in tun["route_exclude_address"]

    rules = cfg["route"]["rules"]
    assert len(rules) == 1
    assert "source_port" not in rules[0]
    assert rules[0]["process_name"] == ["Target.exe"]
    assert rules[0]["ip_cidr"] == ["104.29.0.0/16"]
    assert rules[0]["outbound"] == "screen-socks"
    assert cfg["route"]["final"] == "direct"

    socks = [o for o in cfg["outbounds"] if o["type"] == "socks"][0]
    assert socks["network"] == "udp"
