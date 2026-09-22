"""Minimal self-check for the free-IP allocation and range-lookup logic."""
import pfsense


def test_range_of():
    assert pfsense.range_of("192.0.2.5") == "office"
    assert pfsense.range_of("192.0.2.20") == "cctv"
    assert pfsense.range_of("203.0.113.1") is None


def test_next_free_ip(monkeypatch):
    monkeypatch.setattr(pfsense, "list_static_mappings", lambda: [
        {"ipaddr": "192.0.2.1"}, {"ipaddr": "192.0.2.2"},
    ])
    assert pfsense.next_free_ip("office") == "192.0.2.3"


def test_next_free_ip_exhausted(monkeypatch):
    office_hosts = [str(h) for h in pfsense.RANGES["office"].hosts()]
    monkeypatch.setattr(pfsense, "list_static_mappings", lambda: [{"ipaddr": ip} for ip in office_hosts])
    assert pfsense.next_free_ip("office") is None


if __name__ == "__main__":
    class _FakeMonkeypatch:
        def setattr(self, obj, name, value):
            setattr(obj, name, value)

    test_range_of()
    test_next_free_ip(_FakeMonkeypatch())
    test_next_free_ip_exhausted(_FakeMonkeypatch())
    print("ok")
