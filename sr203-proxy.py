#!/usr/bin/env python3
"""
sr203-proxy.py — a tiny LAN proxy that makes the Sky Hub SR203 web UI usable again.

The SR203 firmware replies to *.sky POST requests (every security change) with a
malformed HTTP/0.9 response: a bare HTML body with no status line and no headers.
Modern browsers reject HTTP/0.9, so the GUI shows "Session expired! Please press OK
to refresh the page" even though the change was accepted by the router.

This proxy sits between your browser and the router. It forwards everything verbatim,
but when the router sends an HTTP/0.9 reply it wraps it in a valid HTTP/1.1 response
so the browser accepts it. HTTP Digest auth passes through transparently (the digest
is computed over the method + path, which the proxy preserves).

Usage:
    python3 -I sr203-proxy.py                 # listen on 127.0.0.1:8099 -> 192.168.0.1:80
    python3 -I sr203-proxy.py --listen 0.0.0.0:8099 --target 192.168.0.1:80

Then browse to  http://127.0.0.1:8099/  and use the UI normally.
Stop with Ctrl-C. Stdlib only; no external dependencies.
"""
import argparse
import os
import re
import socket
import sys
import threading

__version__ = "1.4.0"  # bump on release; shown at startup and in X-SR203-Proxy-Version

BUFSZ = 65536

# The SR203 rotates the per-form anti-CSRF "sessionKey" on every page render and only
# accepts the most-recently-issued one. If a render happens between form-load and
# submit, the POST carries a stale key and the firmware returns a "Session expired"
# page. Since all router traffic flows through this proxy, we track the freshest key
# the server has emitted and stamp it onto outgoing POSTs, closing the race.
FIX_SESSIONKEY = os.environ.get("SR203_FIX_SESSIONKEY", "1") not in ("0", "false", "no")
DEBUG = os.environ.get("SR203_DEBUG", "0") not in ("0", "false", "no")
_LAST_KEY = None
_LAST_KEY_LOCK = threading.Lock()


def dbg(*a):
    if DEBUG:
        sys.stderr.write("[sr203] " + " ".join(str(x) for x in a) + "\n")
        sys.stderr.flush()
# The token appears in three forms depending on the page:
#   - a JS variable:  var sessionID = '12345';   (firewall-rules pages; the hidden
#     field there is just a value="0" placeholder the JS overwrites at submit)
#   - a hidden field: name="sessionKey" value="12345"   (block-sites, wireless, …)
#   - a refresh URL:  ...?sessionKey=12345   (the "Session expired" page)
# We must prefer the real value and IGNORE the "0" placeholder — learning "0" and
# stamping it onto a POST is itself what breaks the firewall-rules pages.
_KEY_IN_JS = re.compile(rb"sessionID\s*=\s*'(\d+)'")
_KEY_IN_HTML = re.compile(rb'name="sessionKey"\s+value="(\d+)"', re.I)
_KEY_IN_URL = re.compile(rb'[?&]sessionKey=(\d+)')
_KEY_IN_BODY = re.compile(rb'sessionKey=\d+')


def _note_server_key(body):
    """Remember the most recent *real* sessionKey the server emitted, so we can stamp
    it onto subsequent POSTs. Placeholder zeros are ignored."""
    if not body:
        return
    cands = _KEY_IN_JS.findall(body) + _KEY_IN_HTML.findall(body) + _KEY_IN_URL.findall(body)
    cands = [c for c in cands if c != b"0"]
    if cands:
        with _LAST_KEY_LOCK:
            global _LAST_KEY
            _LAST_KEY = cands[-1]
        dbg("learned sessionKey", _LAST_KEY.decode(), "candidates=", [c.decode() for c in cands])


def recv_http_message(sock, is_request):
    """Read one HTTP message (request or response) from sock.

    Returns (head_bytes, body_bytes, is_http09). For an HTTP/0.9 response (no
    status line beginning with 'HTTP/'), head_bytes is b'' and the whole stream
    is treated as the body.
    """
    data = b""
    # Read until we have the full header block, or the peer closes.
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(BUFSZ)
        if not chunk:
            break
        data += chunk
        # HTTP/0.9 response detection: a real HTTP/1.x message starts with 'HTTP/'
        # (response) or a method token then ' HTTP/1.' (request). For responses,
        # if the first bytes we see are clearly not a status line, treat as 0.9.
        if not is_request and len(data) >= 5 and not data.startswith(b"HTTP/"):
            # Router's HTTP/0.9 reply: no headers at all. Drain to EOF = body.
            while True:
                chunk = sock.recv(BUFSZ)
                if not chunk:
                    break
                data += chunk
            return b"", data, True

    if b"\r\n\r\n" not in data:
        # Connection closed before a full header block.
        if not is_request and data and not data.startswith(b"HTTP/"):
            return b"", data, True
        return data, b"", False

    head, _, rest = data.partition(b"\r\n\r\n")
    head += b"\r\n\r\n"
    body = rest

    # Determine framing from headers.
    content_length = None
    chunked = False
    for line in head.split(b"\r\n"):
        low = line.lower()
        if low.startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                content_length = None
        elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
            chunked = True

    if chunked:
        # Dechunk so we hand the upstream a clean Content-Length body. A reverse
        # proxy (e.g. nginx / Nginx Proxy Manager) in front of us may send request
        # bodies chunked; the SR203's embedded server only understands
        # Content-Length, so normalising here is what makes it work behind a proxy.
        body = _read_chunked_body(sock, body)
    elif content_length is not None:
        while len(body) < content_length:
            chunk = sock.recv(BUFSZ)
            if not chunk:
                break
            body += chunk
    else:
        # No explicit length. Requests: assume no body. Responses: read to EOF
        # (the router delimits with Connection: close).
        if not is_request:
            while True:
                chunk = sock.recv(BUFSZ)
                if not chunk:
                    break
                body += chunk

    return head, body, False


def _read_chunked_body(sock, buf):
    """Decode an HTTP/1.1 chunked transfer-encoded body, reading more from sock as
    needed. `buf` is whatever bytes were already read after the header block."""
    out = b""
    while True:
        while b"\r\n" not in buf:
            more = sock.recv(BUFSZ)
            if not more:
                return out
            buf += more
        size_line, _, buf = buf.partition(b"\r\n")
        size_line = size_line.split(b";", 1)[0].strip()  # ignore chunk extensions
        try:
            n = int(size_line or b"0", 16)
        except ValueError:
            return out
        if n == 0:
            return out  # last chunk; ignore any trailers
        while len(buf) < n + 2:  # chunk data + trailing CRLF
            more = sock.recv(BUFSZ)
            if not more:
                break
            buf += more
        out += buf[:n]
        buf = buf[n + 2:]


def rewrite_request_head(head, target_host):
    """Rewrite headers for the picky SR203 parser.

    - Host: must be the router's address (it 400s on 'Host: 127.0.0.1:8099').
    - Force Connection: close (the firmware closes anyway).
    - Force identity encoding so bodies stay readable.
    - Drop Transfer-Encoding and Content-Length; the caller re-adds a correct
      Content-Length for the (already fully read / dechunked) body, so the SR203
      always receives Content-Length framing even behind a reverse proxy.
    Digest auth is unaffected (it's computed over method + path, both preserved).
    """
    host_b = target_host.encode()
    lines = head.split(b"\r\n")
    out = [lines[0]]  # request line, path preserved (digest is computed over it)
    seen_conn = seen_host = False
    for line in lines[1:]:
        if not line:
            continue
        low = line.lower()
        if low.startswith(b"host:"):
            seen_host = True
            out.append(b"Host: " + host_b)
        elif low.startswith(b"connection:") or low.startswith(b"proxy-connection:"):
            seen_conn = True
            out.append(b"Connection: close")
        elif low.startswith(b"accept-encoding:"):
            out.append(b"Accept-Encoding: identity")  # avoid gzip so bodies stay readable
        elif low.startswith(b"transfer-encoding:") or low.startswith(b"content-length:"):
            continue  # re-added cleanly by set_content_length() when forwarding
        else:
            out.append(line)
    if not seen_host:
        out.append(b"Host: " + host_b)
    if not seen_conn:
        out.append(b"Connection: close")
    return b"\r\n".join(out) + b"\r\n\r\n"


def set_content_length(head, n):
    """Replace (or add) the Content-Length header in a request head block."""
    lines = head.rstrip(b"\r\n").split(b"\r\n")
    out, seen = [], False
    for line in lines:
        if line.lower().startswith(b"content-length:"):
            out.append(b"Content-Length: " + str(n).encode())
            seen = True
        else:
            out.append(line)
    if not seen:
        out.append(b"Content-Length: " + str(n).encode())
    return b"\r\n".join(out) + b"\r\n\r\n"


def maybe_fix_sessionkey(req_head, req_body):
    """For a POST carrying a sessionKey, overwrite it with the freshest key the
    server has issued. Digest qop=auth signs method+URI+nonce (not the body), so
    rewriting the body does not break authentication."""
    if not FIX_SESSIONKEY or not req_body or b"sessionKey=" not in req_body:
        return req_head, req_body
    if not req_head.split(b" ", 1)[0].upper() == b"POST":
        return req_head, req_body
    with _LAST_KEY_LOCK:
        key = _LAST_KEY
    orig = _KEY_IN_BODY.search(req_body)
    if not key or key == b"0":
        dbg("POST sessionKey in body =", orig.group().decode() if orig else "none",
            "| LAST_KEY =", key.decode() if key else "none", "| NOT stamping")
        return req_head, req_body  # never stamp a placeholder over a good token
    new_body = _KEY_IN_BODY.sub(b"sessionKey=" + key, req_body)
    if new_body != req_body:
        req_head = set_content_length(req_head, len(new_body))
    dbg("POST sessionKey in body =", orig.group().decode() if orig else "none",
        "| stamped LAST_KEY =", key.decode(), "| changed =", new_body != req_body)
    return req_head, new_body


def synth_http11(body):
    """Wrap a bare HTTP/0.9 body in a minimal valid HTTP/1.1 response."""
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"X-SR203-Proxy: upgraded-http0.9\r\n"
        b"X-SR203-Proxy-Version: " + __version__.encode() + b"\r\n"
        b"\r\n"
    )
    return headers + body


def add_version_header(resp_head):
    """Insert the proxy version header after the status line of a relayed response, so
    `curl -I` against the proxy reveals exactly which build is running."""
    if not resp_head.startswith(b"HTTP/"):
        return resp_head
    status, _, rest = resp_head.partition(b"\r\n")
    return status + b"\r\nX-SR203-Proxy-Version: " + __version__.encode() + b"\r\n" + rest


def handle_client(client, target_host, target_port):
    try:
        req_head, req_body, _ = recv_http_message(client, is_request=True)
        if not req_head:
            return
        if DEBUG:
            dbg(">>", req_head.split(b"\r\n", 1)[0].decode(errors="replace"))
        req_head = rewrite_request_head(req_head, target_host)
        req_head, req_body = maybe_fix_sessionkey(req_head, req_body)
        # Always forward with explicit Content-Length framing (head rewrite stripped
        # any Transfer-Encoding / Content-Length). Only emit it when there's a body
        # so plain GETs stay clean.
        if req_body:
            req_head = set_content_length(req_head, len(req_body))

        with socket.create_connection((target_host, target_port), timeout=20) as upstream:
            upstream.sendall(req_head + req_body)
            resp_head, resp_body, is09 = recv_http_message(upstream, is_request=False)

        if DEBUG and b"Session expired" in resp_body:
            dbg("<< response was a SESSION EXPIRED page")

        # Learn the freshest sessionKey the server hands out (form page or refresh URL).
        _note_server_key(resp_body)

        if is09:
            client.sendall(synth_http11(resp_body))
        else:
            client.sendall(add_version_header(resp_head) + resp_body)
    except Exception as e:  # noqa: BLE001 - best-effort proxy, log and move on
        try:
            msg = f"proxy error: {e}".encode()
            client.sendall(synth_http11(b"<html><body>" + msg + b"</body></html>"))
        except OSError:
            pass
    finally:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client.close()


def parse_hostport(s, default_port):
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, default_port


def main():
    ap = argparse.ArgumentParser(description="SR203 HTTP/0.9 response-fixing proxy")
    ap.add_argument("--listen", default=os.environ.get("SR203_LISTEN", "127.0.0.1:8099"),
                    help="listen address (env SR203_LISTEN; default 127.0.0.1:8099)")
    ap.add_argument("--target", default=os.environ.get("SR203_TARGET", "192.168.0.1:80"),
                    help="router address (env SR203_TARGET; default 192.168.0.1:80)")
    args = ap.parse_args()

    lhost, lport = parse_hostport(args.listen, 8099)
    thost, tport = parse_hostport(args.target, 80)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lhost, lport))
    srv.listen(64)
    print(f"SR203 proxy v{__version__}: http://{lhost}:{lport}/  ->  {thost}:{tport}")
    print("Browse to the listen URL and use the Sky Hub UI normally. Ctrl-C to stop.")
    try:
        while True:
            client, _ = srv.accept()
            threading.Thread(
                target=handle_client, args=(client, thost, tport), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
