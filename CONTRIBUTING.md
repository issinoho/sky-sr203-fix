# Contributing

Thanks for helping improve **sky-sr203-fix**! This is a small community workaround, so
anything is welcome — bug reports, compatibility reports from other Sky Hub models,
docs fixes, or code.

## 🔒 Before you post anything

**Never include secrets in issues, logs, screenshots, or pull requests:**

- router **admin password** or Wi-Fi **passphrase**
- device **serial number**, MAC addresses, or the sticker details
- anything from a `.sr203_netrc` / `.proxy_netrc` / `.env` file

Redact logs before pasting (replace real values with `xxxxx`). The repo's `.gitignore`
blocks credential files from being committed — please keep it that way.

## Reporting a bug

Open an issue using the **Bug report** template. Useful details: your hub model, which
tool and run mode (Docker / systemd / foreground / script), what you did, what happened
vs. what you expected, and redacted logs (`docker compose logs` or
`journalctl -u sr203-proxy`).

## "Does it work on my hub?"

If you have a Sky Hub that is **not** an SR203, please try it and open a
**Compatibility report** — whether it works or not is equally useful. Include the model
number (on the sticker), the `Server:` banner (`curl -sI http://192.168.0.1/ | grep -i server`),
and the UI version shown in the page footer.

## Code changes

1. Keep it **dependency-free** — the proxy is Python 3 standard library only; the script
   is `bash` + `curl`. Please don't add runtime dependencies.
2. Test against a real SR203 where possible, and say so in the PR.
3. Match the existing style; keep changes focused.
4. Run the basic checks:
   ```bash
   bash -n sr203.sh
   python3 -c "import ast; ast.parse(open('sr203-proxy.py').read())"
   ```

## Ideas that would help

- Wrapping more endpoints in `sr203.sh` (port forwarding, DHCP reservations, DMZ…).
- Packaging: Home Assistant add-on, OpenWrt/entware, `.deb`.
- Confirmation of behaviour on other Sky Hub firmware revisions.

By contributing you agree your contributions are licensed under the repo's
[MIT License](LICENSE).
