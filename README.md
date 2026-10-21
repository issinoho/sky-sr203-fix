# sky-sr203-fix

**Fix the "Session expired ! Please press OK to refresh the page" error on the Sky
Hub SR203 router.**

If you own a Sky **SR203** (Sky Hub / Sky Broadband Hub) you may have hit this: every
time you try to change a security setting — a firewall/blocked-sites rule, the Wi-Fi
password, the admin password — the router web page throws:

> **Session expired ! Please press OK to refresh the page**

…and your change appears to fail. This repo explains **why** it happens and gives you
**two ways to fix it**:

| | What it is | Best for |
|---|---|---|
| **🔌 Proxy** (recommended) | A tiny service you run on a PC, Raspberry Pi, NAS or Docker host. Point your browser at it and **the normal Sky Hub web UI just works** — in any modern browser, for your whole household. | Most people. Keeps using the familiar web interface. |
| **⌨️ Script** | A `bash` + `curl` script that makes the changes from the command line, bypassing the browser entirely. | Power users / headless boxes / automation. |

Both are tiny, dependency-free, and run entirely on your own network. Nothing is sent
anywhere.

> ⚠️ **Not affiliated with Sky.** This is a community workaround for a firmware bug.
> Use at your own risk. See [Disclaimer](#disclaimer).

---

## Quick install (proxy)

On a Linux box or Raspberry Pi on your network, this clones the repo and starts the
proxy via **Docker** or **systemd** automatically:

```bash
curl -fsSL https://raw.githubusercontent.com/issinoho/sky-sr203-fix/main/install.sh | bash
```

Then browse to `http://<that-host-ip>:8099/`. Prefer to do it by hand, or pick a
specific method? See the full options below.

> 🔍 Good habit: read any `curl … | bash` script first —
> [`install.sh`](install.sh) only clones this repo and starts the proxy.

---

## Why does this happen?

It's **two firmware bugs stacked on top of each other** — neither is a fault with your
hardware, and nothing is actually wrong with your "session":

1. **Malformed HTTP responses.** When you save a security change, the router's
   handlers (`*.sky`, `*.scgi`, `*.cmd`) reply with a legacy **HTTP/0.9** response —
   a bare page body with *no HTTP status line and no headers*. Modern browsers have
   disabled HTTP/0.9 for security, so your browser rejects the reply and treats the
   save as failed. (The router has usually **already applied the change** before
   sending the broken reply — so settings you thought failed may actually have saved.)

2. **A single-use, rotating session token.** Each security page embeds a hidden
   `sessionKey` that the firmware **regenerates on every page load** and only accepts
   the newest value of. If anything re-renders a page between loading the form and
   submitting it (a background status poll, a second browser tab), your token is stale
   and the server returns the "Session expired" page — which then reloads the form
   with a fresh token, which is why a **retry often works**.

Browsers used to tolerate both behaviours; as they tightened up, the bug became
visible. **Both fixes in this repo address both bugs.** For the gory details see
[How it works](#how-it-works).

**Affected model:** developed and verified on the **SR203**. Other Sky Hubs that use
the same `sky_router` web firmware may behave identically — reports welcome (open an
issue).

---

## Option A — The Proxy (recommended)

The proxy sits between your browser and the router. It forwards everything unchanged
except that it **repairs the malformed HTTP/0.9 replies** and **stamps the freshest
`sessionKey` onto your saves** — so the web UI behaves normally. Your router login
(HTTP Digest) passes straight through; **the proxy never sees or stores your password.**

Run it whichever way suits your setup:

- **[A1. Docker container](#a1-as-a-docker-container-easiest)** — one command, auto-restarts, isolated.
- **[A2. systemd daemon](#a2-as-a-systemd-service-daemon)** — runs on boot on any Linux box, no Docker needed.
- **[A3. Foreground / quick test](#a3-foreground-quick-test)** — just `python3`, nothing installed.

### A1. As a Docker container (easiest)

**Prerequisites:** a machine on your LAN with Docker + Docker Compose (a PC, NAS, or
Raspberry Pi is ideal).

```bash
git clone https://github.com/issinoho/sky-sr203-fix.git
cd sky-sr203-fix

# optional: change the port or router address
cp .env.example .env        # then edit if needed

docker compose up -d --build
```

Then on **any** device on your network, browse to:

```
http://<docker-host-ip>:8099/
```

…and log in / use the Sky Hub interface exactly as normal. Security changes now work
first time.

**Configuration** (via `.env`):

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_PORT` | `8099` | Port to reach the proxy on (`http://<host>:PROXY_PORT/`) |
| `ROUTER_ADDR` | `192.168.0.1:80` | Your Sky Hub's address (the default for Sky) |
| `FIX_SESSIONKEY` | `1` | Stamp the fresh session token onto saves (leave on) |

Manage it with:
```bash
docker compose logs -f      # watch activity
docker compose restart
docker compose down         # stop & remove
```

### A2. As a systemd service (daemon)

Runs on boot on any Linux machine (PC, Raspberry Pi, NAS) with **no Docker** — the
proxy is pure Python 3 standard library, so there's nothing to install.

```bash
# 1. Put the code somewhere stable:
sudo git clone https://github.com/issinoho/sky-sr203-fix.git /opt/sky-sr203-fix

# 2. Install the service unit (edit it first if your paths/router differ):
sudo cp /opt/sky-sr203-fix/sr203-proxy.service /etc/systemd/system/

# 3. Enable + start it:
sudo systemctl daemon-reload
sudo systemctl enable --now sr203-proxy.service
```

Then browse to `http://<that-machine-ip>:8099/`.

Manage and inspect it with:
```bash
systemctl status sr203-proxy        # is it running?
journalctl -u sr203-proxy -f        # live logs
sudo systemctl restart sr203-proxy
sudo systemctl disable --now sr203-proxy   # stop & don't start on boot
```

**Configuration** lives in the unit file (`/etc/systemd/system/sr203-proxy.service`):
edit the `Environment=` lines for `SR203_LISTEN`, `SR203_TARGET`, `SR203_FIX_SESSIONKEY`
and the `WorkingDirectory`/`ExecStart` paths, then `sudo systemctl daemon-reload &&
sudo systemctl restart sr203-proxy`. The shipped unit is hardened (runs as a
`DynamicUser`, no privileges, read-only filesystem). If you set a listen **port below
1024**, see the comment in the unit about `CAP_NET_BIND_SERVICE`.

### A3. Foreground / quick test

No install at all — just run it and leave the terminal open:

```bash
git clone https://github.com/issinoho/sky-sr203-fix.git
cd sky-sr203-fix

# listen on all interfaces so other devices can use it:
python3 -I sr203-proxy.py --listen 0.0.0.0:8099 --target 192.168.0.1:80
```

Browse to `http://<that-machine-ip>:8099/`. Press `Ctrl-C` to stop.

Options (all three run modes accept these): `--listen HOST:PORT` (default
`127.0.0.1:8099`), `--target HOST:PORT` (default `192.168.0.1:80`), or the env vars
`SR203_LISTEN` / `SR203_TARGET` / `SR203_FIX_SESSIONKEY`.

### Verifying it works

Open the proxy URL, go to **Firewall Rules / Block Sites** (or Wireless), make a
change, and click **Apply**. It should save without the "Session expired" popup. If
you'd previously tried changes that "failed", check them — some may have applied.

---

## Option B — The Script

`sr203.sh` makes changes directly via `curl`, bypassing the browser. Good for headless
systems or scripting.

**Prerequisites:** `bash` and `curl` (both standard on Linux/macOS; on Windows use WSL
or Git Bash).

### Set up credentials

The script authenticates with your router admin password using a `curl` **netrc** file,
so the password never appears on the command line or in your shell history:

```bash
cd sky-sr203-fix
umask 077
printf 'machine 192.168.0.1 login admin password YOUR_ADMIN_PASSWORD\n' > .sr203_netrc
```

(`.sr203_netrc` is git-ignored so it can't be committed.) The default username on the
SR203 is `admin`.

### Commands

```bash
./sr203.sh list-sites                 # show currently blocked keywords
./sr203.sh block-site ads-tracker     # block URLs containing a keyword (min 3 chars)
./sr203.sh unblock-site ads-tracker   # remove a blocked keyword

./sr203.sh set-admin-password         # change the router admin password
./sr203.sh set-wifi-password          # change the Wi-Fi WPA2 passphrase

./sr203.sh get sky_wireless_settings.html          # fetch any admin page (inspection)
./sr203.sh raw-post sky_<endpoint>.sky key=val ... # advanced: hand-crafted POST
./sr203.sh --help
```

**Password changes** prompt for the new value with no echo (or read it from an env var
— `SR203_NEW_PW` for admin, `SR203_WIFI_PW` for Wi-Fi — never a command-line argument):

- `set-admin-password`: new password 1–16 chars, must differ from the current one.
  After changing it **verifies the new password works and updates your netrc**, so you
  can't get silently locked out.
- `set-wifi-password`: WPA passphrase 8–63 chars. **WPA2-PSK / WPA+WPA2-PSK only**
  (it refuses WEP/open/RADIUS rather than guess). ⚠️ Changing the Wi-Fi key
  **disconnects all wireless devices** until they reconnect with the new key. If your
  hub has the 2.4 GHz and 5 GHz bands on the same SSID with "Synchronise … Settings"
  turned off, set the same key you want on both.

**Configuration** (env vars): `SR203_HOST` (default `192.168.0.1`), `SR203_NETRC`
(default `./.sr203_netrc`).

---

## Which router address / is mine affected?

- On Sky, the hub is almost always at **`192.168.0.1`** (the defaults here assume that).
- Log in at `http://192.168.0.1/`; if the server banner is `sky_router` and the page
  footer shows a `v4.x` UI, you have the affected firmware family.
- Default admin username is `admin`; the password is on the sticker unless you changed
  it.

---

## Security & privacy

- **Everything runs on your LAN.** Neither tool contacts the internet or any third
  party. There is no telemetry.
- **The proxy stores no credentials.** Your browser still logs in to the router with
  HTTP Digest auth; the proxy just relays it. It adds no new exposure beyond what the
  router's own web UI already has on your network — but still, only publish the proxy
  port on a network you trust (don't forward it from the internet).
- **The script's password** lives only in the local `.sr203_netrc` file (mode `600`,
  git-ignored). Delete it when done: `rm -f .sr203_netrc`.
- Rewriting the request body is safe for authentication because HTTP Digest signs the
  method + URL + nonce, **not** the body.

---

## Troubleshooting

- **"Session expired" still appears once, then works.** You're likely running an older
  build of the proxy — rebuild/redeploy (`docker compose up -d --build`) and hard-
  refresh the browser to clear a cached form page.
- **Browser can't reach the proxy.** Check the host's firewall allows the port, and
  that you started it with `--listen 0.0.0.0:8099` (not `127.0.0.1`) if browsing from
  another device.
- **`400 Bad Request` from the router.** The proxy rewrites the `Host:` header for you;
  if you hand-roll `curl` against the router, keep `Host: 192.168.0.1`.
- **My hub isn't at `192.168.0.1`.** Set `ROUTER_ADDR` / `--target` / `SR203_HOST`
  accordingly.
- **Script says "could not read sessionKey (auth problem?)".** Your netrc password is
  wrong, or the username isn't `admin`.

### Running behind another reverse proxy (Nginx Proxy Manager, Traefik, Caddy…)

Supported — put this proxy upstream of your usual reverse proxy and point your browser
at the nice hostname. A few tips:

- **Use a subdomain** (e.g. `sr203.yourdomain`), not a subpath (`/sr203/`). The router's
  pages use root-relative URLs and HTTP Digest auth tied to the request path, so a
  subpath mount breaks them.
- In **Nginx Proxy Manager**: add a Proxy Host → Forward Hostname/IP = the machine
  running `sr203-proxy`, Forward Port = `8099`, scheme `http`. Leave caching off.
- This proxy **normalises request framing** (it dechunks `Transfer-Encoding: chunked`
  bodies and forwards clean `Content-Length` to the router), which is what makes saves
  work behind nginx — older builds showed "Session expired" here, so **rebuild/redeploy**
  if you're upgrading.

---

## How it works

<details>
<summary>Technical deep-dive (click to expand)</summary>

### Fault 1 — HTTP/0.9 responses

A read-only `GET` returns a proper `HTTP/1.1` response. But an authenticated `POST` to
a `*.sky` / `*.scgi` / `*.cmd` write handler returns a body with **no status line and
no headers**, e.g.:

```
<html>
<head><meta http-equiv='refresh' content='0; URL=sky_block_sites.html' /></head></html>
```

That's an HTTP/0.9-style reply. `curl` reports `Received HTTP/0.9 when not allowed`;
browsers reject it too. Forcing `curl --http0.9` accepts it and the change applies —
proving the server processed the request and only the *response framing* is broken.
The proxy detects a response that doesn't begin with `HTTP/` and wraps it in a valid
`HTTP/1.1 200` with headers.

### Fault 2 — rotating `sessionKey`

Each security form embeds `<input name="sessionKey" value="…">`. Fetching the same
page twice yields **different** values — the firmware regenerates it per render and
only honours the latest. Submit a stale one and the server returns:

```html
<script>function formLoad(){ alert("Session expired ! Please press OK to refresh the page")}</script>
... onload="formLoad()"><meta http-equiv='refresh' content='0;URL=sky_block_sites.html?sessionKey=NEW' />
```

Because **all** router traffic flows through the proxy, it watches the `sessionKey`
values the server emits and rewrites outgoing POSTs to carry the freshest one, closing
the race. The script achieves the same by fetching a fresh key immediately before each
save.

### The proper fix

The real defect is in the firmware: the write handlers should emit compliant HTTP
responses, and the session token shouldn't be single-use/racy. That requires a firmware
update from Sky. This repo is a client-side workaround in the meantime.

</details>

---

## Contributing

Issues and PRs welcome — especially:
- Reports from **other Sky Hub models** (does the same workaround help?).
- Additional endpoints wrapped in `sr203.sh` (port forwarding, DHCP reservations, …).
- Packaging (systemd unit, Home Assistant add-on, etc.).

Please don't include your router password, serial number, or Wi-Fi key in issues/logs.

---

## Disclaimer

This project is an independent, community-made workaround. It is **not affiliated with,
endorsed by, or supported by Sky**. "Sky" and "Sky Hub" are trademarks of their
respective owners. The software is provided "as is" without warranty of any kind (see
[LICENSE](LICENSE)). You are responsible for how you use it on your own equipment and
network.

## License

[MIT](LICENSE) © Iain Smith
