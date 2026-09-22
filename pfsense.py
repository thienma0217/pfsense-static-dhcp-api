"""Thin client for a pfSense box's static DHCP mappings on one interface.

Reuses the same routers.yml credentials and REST API (pfSense-pkg-API v2)
as ~/GoogleDriveSync/pfsense-mcp/mcp-server/server.py.
"""
import ipaddress
import os
from pathlib import Path

import httpx
import yaml

ROUTER_NAME = os.environ.get("PFSENSE_ROUTER", "pfsense")
INTERFACE = os.environ.get("PFSENSE_INTERFACE", "opt2")
ROUTERS_YML = Path(os.environ.get(
    "PFSENSE_ROUTERS_YML",
    Path(__file__).resolve().parent.parent / "pfsense-mcp" / "routers.yml",
))


def _parse_ranges(spec):
    """STATIC_IP_RANGES="office:10.0.0.0/28:Office,cctv:10.0.1.0/27:CCTV" """
    ranges, labels = {}, {}
    for part in spec.split(","):
        key, cidr, label = part.split(":")
        ranges[key] = ipaddress.ip_network(cidr)
        labels[key] = label
    return ranges, labels


RANGES, RANGE_LABELS = _parse_ranges(os.environ.get(
    "STATIC_IP_RANGES", "office:192.0.2.0/28:Office,cctv:192.0.2.16/28:CCTV",
))


class PfSenseError(RuntimeError):
    pass


def _load_router():
    # Plain env vars take priority - lets a deployed container skip mounting
    # the sibling pfsense-mcp checkout and its routers.yml.
    url = os.environ.get("PFSENSE_URL")
    if url:
        return {"url": url, "user": os.environ["PFSENSE_USER"], "pass": os.environ["PFSENSE_PASS"]}
    entries = yaml.safe_load(ROUTERS_YML.read_text()) or []
    for entry in entries:
        info = entry["info"]
        name = info.get("hostname") or info.get("url")
        if name == ROUTER_NAME:
            return {"url": entry["servers"][0], "user": info["user"], "pass": info["pass"]}
    raise RuntimeError(f"Router '{ROUTER_NAME}' not found in {ROUTERS_YML}")


def _client() -> httpx.Client:
    global _cached_client
    try:
        return _cached_client
    except NameError:
        pass
    router = _load_router()
    _cached_client = httpx.Client(
        base_url=router["url"].rstrip("/") + "/api/v2",
        auth=(router["user"], router["pass"]),
        verify=False,
        timeout=15,
    )
    return _cached_client


def _call(method, path, **kwargs):
    try:
        resp = _client().request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        raise PfSenseError(f"Không kết nối được tới pfSense: {exc}") from exc

    try:
        body = resp.json()
    except ValueError:
        raise PfSenseError(
            f"pfSense trả về phản hồi không hợp lệ (HTTP {resp.status_code}). "
            "Có thể sai user/pass hoặc IP bị pfSense tạm khoá do đăng nhập sai nhiều lần."
        )
    if body.get("code") != 200:
        raise PfSenseError(body.get("message") or body.get("response_id") or "pfSense API error")
    return body["data"]


def list_static_mappings():
    return _call("GET", "/services/dhcp_server/static_mappings", params={"parent_id": INTERFACE, "limit": 0})


def apply_changes():
    # Static-mapping writes stage a config change; pfSense won't act on it
    # (won't hand out/revoke the lease) until this is called.
    _call("POST", "/services/dhcp_server/apply")


def add_static_mapping(mac, ip, descr):
    result = _call("POST", "/services/dhcp_server/static_mapping", json={
        "parent_id": INTERFACE, "mac": mac, "ipaddr": ip, "descr": descr,
    })
    apply_changes()
    return result


def update_static_mapping(mapping_id, mac, descr):
    result = _call("PATCH", "/services/dhcp_server/static_mapping", json={
        "parent_id": INTERFACE, "id": mapping_id, "mac": mac, "descr": descr,
    })
    apply_changes()
    return result


def delete_static_mappings(ids):
    # pfSense ids are array indices: deleting one shifts later ones down,
    # so delete highest-id first to keep the remaining ids valid.
    for mapping_id in sorted(set(ids), reverse=True):
        _call("DELETE", "/services/dhcp_server/static_mapping",
              params={"parent_id": INTERFACE, "id": mapping_id})
    apply_changes()


def range_of(ip):
    addr = ipaddress.ip_address(ip)
    for key, net in RANGES.items():
        if addr in net:
            return key
    return None


def next_free_ip(range_key, exclude=()):
    net = RANGES[range_key]
    used = {m["ipaddr"] for m in list_static_mappings()} | set(exclude)
    for host in net.hosts():
        if str(host) not in used:
            return str(host)
    return None


def online_status_map():
    """{ip: True/False} from pfSense's own DHCP lease status (its ARP-table check,
    not ICMP) — works even when a Windows client's firewall blocks ping."""
    leases = _call("GET", "/status/dhcp_server/leases", params={"limit": 0})
    return {l["ip"]: l["online_status"] == "active/online" for l in leases}


def usage_summary():
    mappings = list_static_mappings()
    counts = {k: 0 for k in RANGES}
    for m in mappings:
        r = range_of(m["ipaddr"])
        if r:
            counts[r] += 1
    usage = {
        key: {
            "used": counts[key], "total": RANGES[key].num_addresses - 2,
            "label": RANGE_LABELS[key], "cidr": str(RANGES[key]),
        }
        for key in RANGES
    }
    for u in usage.values():
        u["pct"] = round(u["used"] / u["total"] * 100) if u["total"] else 0
    return usage
