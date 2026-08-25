"""Central configuration for application-level selective split routing."""

PROXY_SOURCES_PRIMARY = [
    # Keep several independent feeds. The scraper deduplicates IP:PORT entries,
    # so overlapping lists do not make the checker probe the same relay twice.
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/proxylist-to/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/gproxynet/free-proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",

]

# Very large feeds are fallback-only. They are not downloaded unless the
# smaller primary feeds fail to produce even MIN_PROXIES usable relays.
PROXY_SOURCES_FALLBACK = [
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/mzyui/proxy-list/main/socks5.txt",
]

# Backwards-compatible aggregate for tools that still import PROXY_SOURCES.
PROXY_SOURCES = PROXY_SOURCES_PRIMARY + PROXY_SOURCES_FALLBACK

# Fast checker defaults. Cache validation normally finishes in a few seconds;
# the full public-list scan is only used when cached relays have died.
CHECK_CONCURRENCY = 220
CONNECT_TIMEOUT = 2.8
LIVENESS_TIMEOUT = 1.0
TLS_TIMEOUT = 4.5
PER_PROXY_TLS_TIMEOUT = 10.0
TLS_BATCH_SIZE = 4
SCAN_CHUNK_SIZE = 4000
LATENCY_SAMPLES = 1

MIN_PROXIES = 1
TOP_PROXIES = 2
RESCRAPE_INTERVAL = 0.0

# A saved harvested inventory has no mandatory expiry. It is tried before any
# new network scrape; public sources are refreshed only when the local inventory
# can no longer produce MIN_PROXIES valid relays.
SCANNED_PROXY_INVENTORY = "runtime/scanned_proxies.txt"

# The application-level PAC is an allowlist: only these small control/session
# destinations can use the SOCKS relay. Everything else is DIRECT at the OS
# networking stack and never enters sing-box.
PAC_PROXY_EXACT_HOSTS = [
    "discord.com",
    "api.discord.com",
]
PAC_PROXY_HOST_PATTERNS = [
    "gateway*.discord.gg",
]

# Explicit direct exceptions are checked before the allowlist. They are useful
# when a hostname belongs to the same parent domain as an allowed control host.
PAC_DIRECT_EXACT_HOSTS = [
    "updates.discord.com",
]
PAC_DIRECT_HOST_PATTERNS = [
    "*.discord.media",
    "*.discordapp.com",
    "*.discordapp.net",
    "*.discordcdn.com",
]

# Only the initial access/session window needs the foreign relay by default.
# After this time, new URL requests are DIRECT. Existing long-lived sockets may
# remain on the relay until they reconnect. Set 0 on the CLI to keep the PAC
# allowlist proxied for the whole application lifetime.
DEFAULT_PROXY_WINDOW_SECONDS = 25
LOCAL_SOCKS_HOST = "127.0.0.1"
LOCAL_SOCKS_PORT_START = 17980
LOCAL_SOCKS_PORT_END = 18020


# v13 experimental screen-share UDP tunnel.  The startup path remains the
# PAC/TCP design; these settings are used only with --tunnel-screen.
UDP_PROXY_TIMEOUT = 2.0
UDP_PROXY_CONCURRENCY = 320
UDP_PROXY_SCAN_CHUNK_SIZE = 1200
UDP_PROXY_DNS_TARGET = ("1.1.1.1", 53)
# Reject relays that technically implement UDP ASSOCIATE but are already too
# slow during the probe to have a realistic chance of establishing RTC.
UDP_PROXY_MAX_TOTAL_MS = 1500.0
UDP_PROXY_MAX_RTT_MS = 700.0
SCREEN_TUN_ROUTE_PREFIX = 16
SCREEN_TUN_INTERFACE_NAME = "ast-rtc"
SCREEN_TUN_ADDRESS = "172.28.240.1/30"

# v13.3 foreign UDP hunt. Fresh metadata-backed feeds are tried before the
# historical giant inventory. The egress country is verified with STUN + GeoIP.
UDP_FOREIGN_EXCLUDED_COUNTRIES = ["BR"]
UDP_FOREIGN_PREFLIGHT_TIMEOUT = 1.6
UDP_FOREIGN_DEEP_TIMEOUT = 2.0
UDP_FOREIGN_MAX_MEDIAN_RTT_MS = 550.0
UDP_FOREIGN_MAX_P95_RTT_MS = 900.0
UDP_FOREIGN_DEEP_SAMPLES = 5
UDP_FOREIGN_MIN_DEEP_SUCCESS = 4
UDP_FAILURE_COOLDOWN_SECONDS = 3600.0

# Small/fresh SOCKS5 feeds used specifically by the UDP hunter. Metadata from
# ProxyScrape is loaded separately and gets first priority.
PROXY_SOURCES_UDP_FRESH = [
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
    "https://raw.githubusercontent.com/Sage520/Proxy-List/main/socks5.txt",
]
