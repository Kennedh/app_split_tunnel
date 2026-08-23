"""Central configuration for application-level selective split routing."""

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
]

# Fast checker defaults. Cache validation normally finishes in a few seconds;
# the full public-list scan is only used when cached relays have died.
CHECK_CONCURRENCY = 140
CONNECT_TIMEOUT = 3.2
LIVENESS_TIMEOUT = 1.6
TLS_TIMEOUT = 4.5
PER_PROXY_TLS_TIMEOUT = 10.0
TLS_BATCH_SIZE = 4
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
