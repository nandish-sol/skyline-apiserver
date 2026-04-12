"""Microsoft DNS client for DNS & IPAM panel.

Uses DNS protocol (dnspython) — SOA queries + AXFR zone transfers.
"""

from __future__ import annotations

import logging

from starlette.concurrency import run_in_threadpool

LOG = logging.getLogger(__name__)


def _parse_host(conn: dict) -> str:
    url = conn["api_url"]
    return url.replace("dns://", "").replace("/", "").split(":")[0]


def _get_zone_names(conn: dict) -> list[str]:
    zones_str = conn.get("dns_view", "")
    return [z.strip() for z in zones_str.split(",") if z.strip()]


def _sync_test(host: str) -> dict:
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [host]
    resolver.port = 53
    resolver.timeout = 10
    resolver.lifetime = 15
    resolver.resolve(".", "NS")
    return {"ok": True}


async def test_connection(conn: dict) -> dict:
    host = _parse_host(conn)
    try:
        await run_in_threadpool(_sync_test, host)
        return {
            "ok": True,
            "message": f"Connected to {host}",
            "grid_ref": f"Microsoft DNS ({host})",
            "status": "active",
        }
    except Exception as e:
        return {
            "ok": False,
            "message": str(e)[:500],
            "grid_ref": "",
            "status": "error",
        }


def _sync_zone_list(host: str, zone_names: list[str]) -> list[dict]:
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [host]
    resolver.port = 53
    resolver.timeout = 10
    resolver.lifetime = 15
    result = []
    for zname in zone_names:
        try:
            answer = resolver.resolve(zname, "SOA")
            soa = answer[0]
            result.append({
                "id": zname,
                "fqdn": zname,
                "view": "default",
                "soa_serial": str(soa.serial),
                "ns_group": "",
            })
        except Exception:
            result.append({
                "id": zname,
                "fqdn": zname,
                "view": "unreachable",
                "soa_serial": "",
                "ns_group": "",
            })
    return result


async def list_zones(conn: dict) -> list[dict]:
    host = _parse_host(conn)
    zone_names = _get_zone_names(conn)
    return await run_in_threadpool(_sync_zone_list, host, zone_names)


def _sync_record_list(host: str, zone_names: list[str]) -> list[dict]:
    import dns.query
    import dns.rdatatype
    import dns.zone

    records = []
    for zname in zone_names:
        try:
            xfr = dns.query.xfr(host, zname, timeout=10)
            z = dns.zone.from_xfr(xfr)
            for name, node in z.nodes.items():
                fqdn = f"{name}.{zname}" if str(name) != "@" else zname
                for rdataset in node.rdatasets:
                    rtype = dns.rdatatype.to_text(rdataset.rdtype)
                    if rtype in ("SOA", "NS"):
                        continue
                    for rdata in rdataset:
                        records.append({
                            "id": f"{fqdn}_{rtype}",
                            "name": fqdn,
                            "type": rtype,
                            "value": str(rdata),
                            "view": zname,
                            "ttl": str(rdataset.ttl),
                            "comment": "",
                        })
        except Exception:
            for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "PTR"):
                try:
                    import dns.resolver

                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [host]
                    resolver.port = 53
                    resolver.timeout = 10
                    answer = resolver.resolve(zname, rtype)
                    for rdata in answer:
                        records.append({
                            "id": f"{zname}_{rtype}",
                            "name": zname,
                            "type": rtype,
                            "value": str(rdata),
                            "view": zname,
                            "ttl": str(answer.rrset.ttl),
                            "comment": "",
                        })
                except Exception:
                    pass
    return records


async def list_records(conn: dict, zone: str | None = None) -> list[dict]:
    host = _parse_host(conn)
    zone_names = [zone] if zone else _get_zone_names(conn)
    return await run_in_threadpool(_sync_record_list, host, zone_names)


async def grid_members(conn: dict) -> list[dict]:
    host = _parse_host(conn)
    return [{
        "id": host,
        "host_name": host,
        "ipv4addr": host,
        "platform": "Microsoft DNS",
        "status": conn.get("status", "UNKNOWN").upper(),
    }]
