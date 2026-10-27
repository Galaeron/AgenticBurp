"""Loopback servers for tests that point a real browser at them.

Chromium refuses to connect to a fixed list of ports (net::ERR_UNSAFE_PORT), so a
browser test whose server binds port 0 fails, for reasons unrelated to what it
checks, whenever the OS hands out one of them. This host's dynamic range starts
at 1024, so 2049 (nfs) does turn up.
"""
from __future__ import annotations

# Chromium's net/base/port_util.cc kRestrictedPorts: the ports it will not
# navigate or fetch to. Transcribed by hand; diff against upstream when the
# bundled Chromium moves on.
CHROMIUM_RESTRICTED_PORTS = frozenset({
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
    101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161,
    179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563,
    587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061,
    6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
})


def bind_browser_safe(bind, attempts: int = 25):
    """The server `bind()` returns, once its port is one Chromium will connect to.

    `bind()` binds port 0 and returns the server (anything with `server_address`
    and `server_close()`). While the port it got is restricted, that server is
    closed and `bind()` is called again, at most `attempts` times in all."""
    for _ in range(attempts):
        server = bind()
        if server.server_address[1] not in CHROMIUM_RESTRICTED_PORTS:
            return server
        server.server_close()
    raise RuntimeError(f"no browser-safe loopback port in {attempts} attempts")
