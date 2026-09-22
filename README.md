# DHCP Static IP Tool

Static DHCP assignment on one pfSense interface, without logging into pfSense.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export ADMIN_EMAIL=you@example.com
export ADMIN_PASSWORD='change-me-now'
export PFSENSE_URL=https://192.0.2.1/
export PFSENSE_USER=admin
export PFSENSE_PASS='change-me'
export STATIC_IP_RANGES='office:10.0.0.0/28:Office,cctv:10.0.1.0/27:CCTV'
# optional, for sending invite emails; without these the invite link is shown on screen instead
export SMTP_HOST=smtp.example.com
export SMTP_USER=...
export SMTP_PASS=...

.venv/bin/python app.py   # http://127.0.0.1:5000
```

`ADMIN_EMAIL`/`ADMIN_PASSWORD` only seed the admin account on first run (when the
`users` table is empty); change the password from the Account tab afterwards.

`STATIC_IP_RANGES` is a comma-separated list of `key:cidr:label` triples — one
static-IP pool per key, shown as tabs/pills throughout the UI.

Credentials for pfSense are read from `../pfsense-mcp/routers.yml` (override
with `PFSENSE_ROUTERS_YML`, and `PFSENSE_ROUTER` to pick the entry by hostname),
or from `PFSENSE_URL`/`PFSENSE_USER`/`PFSENSE_PASS` env vars if set (used by the
Docker deploy below, since the VM won't have the sibling pfsense-mcp checkout).
Interface defaults to `opt2`; override with `PFSENSE_INTERFACE`.

## Deploy with Docker

```bash
cp .env.example .env
# edit .env: SECRET_KEY, ADMIN_EMAIL, ADMIN_PASSWORD, PFSENSE_URL/USER/PASS, optional SMTP_*

docker compose up -d --build   # http://<vm-ip>:5000
```

Static IPs live on pfSense itself; only accounts and the audit log persist
locally, in `./data/app.db` on the host (bind-mounted into the container).
`docker compose down` then `up` again keeps that data. To upgrade after a code
change: `docker compose up -d --build`.

## Self-check

```bash
.venv/bin/pip install pytest
.venv/bin/pytest test_pfsense.py
```
