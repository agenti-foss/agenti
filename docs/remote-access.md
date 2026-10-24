# Reaching Agenti from the internet

This is for anyone running Agenti on their own box and their own domain. It
uses a **Cloudflare Tunnel**, but the Agenti side (`--behind-proxy`) works the
same with nginx or Caddy on the same machine.

## How it fits together

```
browser ──HTTPS (Cloudflare's certificate)──▶ Cloudflare ──tunnel──▶ cloudflared ──plain HTTP, loopback──▶ Agenti (127.0.0.1:8420)
```

- Browsers talk to Cloudflare over HTTPS with a certificate Cloudflare issues
  and renews. You never create or install one.
- `cloudflared` runs on the **same machine** as Agenti and makes an outbound
  connection to Cloudflare. No inbound port is opened on your router or
  firewall.
- The last hop is plain HTTP over loopback. It never leaves the machine, so
  there is nothing to encrypt, no certificate to trust, and **no need to turn
  off certificate checking anywhere**.
- Agenti listens on `127.0.0.1` only. It is not reachable from your LAN, only
  through the tunnel (or by a local user on the box).

If your tunnel runs on a *different* machine than Agenti, this guide does not
apply: that hop crosses a network and needs real TLS. Use
`sudo agenti gui configure --bind <ip> --tls-cert <your cert> --tls-key <your key>` with a
Cloudflare Origin CA certificate and set the tunnel's `originServerName`.

## 1. Point Agenti at the proxy

```bash
sudo agenti gui configure --bind 127.0.0.1 --no-tls \
     --behind-proxy --hostname agenti.example.com
sudo agenti verify gui
```

(`sudo agenti setup` asks the same thing as its last question.) The setting is
saved in `/etc/agenti/api.conf`, survives every upgrade, and the GUI restarts
with it.

What `--behind-proxy` does, and why:

| Setting | Effect |
|---|---|
| plain HTTP on loopback | no certificate to manage; refused with any non-loopback `--bind` |
| `--hostname` (required) | the only `Host` Agenti answers to (plus `localhost`); anything else gets a 400. Stops DNS rebinding and misrouted vhosts |
| session cookie `Secure` | the browser is on HTTPS even though this hop is not |
| client address header | login throttling needs the caller's real address. Read from `CF-Connecting-IP` (change with `--client-ip-header X-Forwarded-For` for nginx/Caddy; the right-most entry is used), and trusted only from a loopback peer |
| passkey origin | `https://<hostname>` with no port |

## 2. Create the tunnel

Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a tunnel**,
install the connector on the Agenti machine, then add a **Public hostname**:

- Hostname: `agenti.example.com`
- Service type: **HTTP**, URL: **`127.0.0.1:8420`**
- Leave *No TLS Verify* off. It does not apply to an HTTP service.

Cloudflare creates the proxied DNS record for you.

## 3. Cloudflare settings worth turning on

- **Access** (Zero Trust → Access → Applications): put an Access policy in
  front of the hostname. This is a second login *before* Agenti's own, and it
  keeps the login page off the open internet. Agenti works with or without it.
  Prefer a narrow allow-list (your own email, or your identity provider) over
  an open policy.
- **SSL/TLS → Edge Certificates → Minimum TLS Version: 1.2** (or higher).
- **SSL/TLS → Overview**: *Full (strict)* is the right mode for the zone. It
  does not affect tunnel traffic, but protects any other record you add.
- **Security → WAF → Rate limiting rules**: limit `POST /auth/login`,
  `/auth/totp` and `/auth/webauthn/login/*` per IP. Agenti has its own
  throttle (per account and per address); the edge rule stops floods before
  they reach your box.
- Optional: restrict by country in a WAF custom rule.

## 4. Passkeys

Passkeys need a real domain, which you now have. Anyone can use them:

1. Sign in with password and 2FA.
2. **Settings → Security → Passkeys → Add a passkey** (an admin enables
   WebAuthn once under **Settings → Platform**).
3. Sign out and use **Sign in with a passkey**.

Open Agenti at `https://agenti.example.com`, not a LAN address or IP. The
browser ties a passkey to the domain. Agenti shows a hint if you are on the
wrong address.

## nginx or Caddy instead

Run the proxy on the same machine, terminate HTTPS there, and forward to
`http://127.0.0.1:8420`. Pass the client address and keep the original Host:

```
# nginx
proxy_pass http://127.0.0.1:8420;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, never append client input
proxy_buffering off;                             # live agent streams (SSE)
```

Then configure with `--client-ip-header X-Forwarded-For`. If your proxy adds its
own `X-Forwarded-For` line instead of overwriting the header, that still works:
Agenti reads every line and uses the right-most address, the one your proxy added.

**Who holds port 8420.** systemd holds it (`agenti-api.socket`), not the Agenti
process, so the port never comes free during a restart, an upgrade or a crash, and
no other program on the machine can take it and pose as Agenti. `sudo agenti gui
restart` keeps the port; `sudo agenti gui stop` releases it, so a stop also signs
everyone out (a cookie collected by whatever took the port meanwhile is worthless),
and `gui start` and `sudo agenti verify` refuse while any other program listens there.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| 400 *Invalid host header* | the hostname Agenti is configured with differs from the one in the URL. Run `sudo agenti gui configure --hostname <the one you use>` |
| 502 / *Unable to reach the origin* | Agenti is not running (`agenti gui status`) or the tunnel's service URL is not `http://127.0.0.1:8420` |
| login works, then you are signed out at once | cookie not `Secure`-eligible: you are on `http://`, not `https://` |
| passkey says the domain is wrong | opened via IP or a different hostname than `--hostname` |
| everyone gets locked out together | the client-address header is not reaching Agenti. Check `--client-ip-header` matches your proxy |
