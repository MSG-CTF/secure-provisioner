"""Reserve author Waitress workers for reads and direct Kubernetes health probes."""
import ipaddress
import re

BEGIN = "# msgctf-pixel-capacity-v1 begin"
END = "# msgctf-pixel-capacity-v1 end"
GATE = "127.0.0.1:18081"


def private_gate(upstream):
    # This is a single loopback-only pool, shared by all existing authenticated
    # public/preview/score routes. No game code, image, replica or SQLite change.
    return f"""{BEGIN}
http://:18081 {{
 bind 127.0.0.1
 @pixel_submission {{
  method POST
  path /api/v1/submissions
 }}
 handle @pixel_submission {{
  reverse_proxy {upstream} {{
   transport http {{
    max_conns_per_host 2
    keepalive_idle_conns_per_host 2
    response_header_timeout 160s
   }}
  }}
 }}
 handle {{
  reverse_proxy {upstream} {{
   transport http {{
    max_conns_per_host 4
    keepalive_idle_conns_per_host 4
    response_header_timeout 30s
   }}
  }}
 }}
}}
{END}
"""


def pixel_gateway(text, upstream):
    host, port = upstream.rsplit(":", 1)
    address = ipaddress.ip_address(host)
    if address.version != 4 or not address.is_private or address.is_loopback or port != "8080":
        raise ValueError("The reviewed private Pixel service on port 8080 is required")
    expected = private_gate(upstream)
    native_route = r"(?m)^\s*reverse_proxy (?:https?://)?" + re.escape(upstream) + r"(?:\s|$)"
    if BEGIN in text or END in text:
        if text.count(BEGIN) != 1 or text.count(END) != 1 or not text.endswith(expected):
            raise ValueError("Existing Pixel pool differs from the reviewed profile")
        public = text[:text.index(BEGIN)]
        if re.search(native_route, public):
            raise ValueError("An unbounded Pixel route bypasses the private pool")
        if not 1 <= len(re.findall(r"(?m)^\s*reverse_proxy " + re.escape(GATE) + r"\s*\{", public)) <= 8:
            raise ValueError("Reviewed Pixel entry routes were changed")
        return text
    if GATE in text or re.search(r"(?m)^\s*[^\n{}]*:18081\s*\{", text):
        raise ValueError("The reviewed loopback port is already used")
    pattern = r"(?m)^([ \t]*)reverse_proxy " + re.escape(upstream) + r"([ \t]*\{)"
    changed, count = re.subn(pattern, lambda m: m[1] + "reverse_proxy " + GATE + m[2], text)
    if not 1 <= count <= 8:
        raise ValueError("Reviewed Pixel native upstream routes were not found")
    if re.search(native_route, changed):
        raise ValueError("An unrecognized Pixel route bypasses the private pool")
    return changed.rstrip() + "\n\n" + expected
