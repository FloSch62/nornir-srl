# Network instance related methods extracted from srlinux.py
from __future__ import annotations

from typing import Any, Dict, List
import datetime
import jmespath


class NetworkInstanceMixin:
    """Mixin providing network-instance related getters."""

    def get_nwi_itf(self, nw_instance: str = "*") -> Dict[str, Any]:
        SUBITF_PATH = "/interface[name=*]/subinterface"
        path_spec = {
            "path": f"/network-instance[name={nw_instance}]",
            "jmespath": '"network-instance"[].{NI:name,oper:"oper-state",type:type,"router-id":protocols.bgp."router-id",\
                    itfs: interface[].{Subitf:name,"assoc-ni":"_other_ni","if-oper":"oper-state", "ip-prefix":*.address[]."ip-prefix",\
                        vlan:vlan.encap."single-tagged"."vlan-id", "mtu":"_mtu"}}',
            "datatype": "state",
        }
        subitf: Dict[str, Any] = {}
        resp = self.get(paths=[SUBITF_PATH], datatype="state")
        for itf in resp[0].get("interface", []):
            for si in itf.get("subinterface", []):
                subif_name = itf["name"] + "." + str(si.pop("index"))
                subitf[subif_name] = si
                subitf[subif_name]["_mtu"] = (
                    si.get("l2-mtu") if "l2-mtu" in si else si.get("ip-mtu", "")
                )

        resp = self.get(
            paths=[path_spec.get("path", "")], datatype=path_spec["datatype"]
        )
        for ni in resp[0].get("network-instance", {}):
            for ni_itf in ni.get("interface", []):
                ni_itf.update(subitf.get(ni_itf["name"], {}))
                if ni_itf["name"].startswith("irb"):
                    ni_itf["_other_ni"] = " ".join(
                        f"{vrf['name']}"
                        for vrf in resp[0].get("network-instance", {})
                        if ni_itf["name"] in [i["name"] for i in vrf["interface"]]
                        and vrf["name"] != ni["name"]
                    )

        res = jmespath.search(path_spec["jmespath"], resp[0])
        return {"nwi_itfs": res}

    def get_lag(self, lag_id: str = "*") -> Dict[str, Any]:
        path_spec = {
            "path": f"/interface[name=lag{lag_id}]",
            "jmespath": '"interface"[].{lag:name, oper:"oper-state",mtu:mtu,"min":lag."min-links",desc:description, type:lag."lag-type", speed:lag."lag-speed","stby-sig":ethernet."standby-signaling",\
                  "lacp-key":lag.lacp."admin-key","lacp-itvl":lag.lacp.interval,"lacp-mode":lag.lacp."lacp-mode","lacp-sysid":lag.lacp."system-id-mac","lacp-prio":lag.lacp."system-priority",\
                    members:lag.member[].{"member-itf":name, "member-oper":"oper-state","act":lacp."activity"}}',
            "datatype": "state",
        }
        resp = self.get(
            paths=[path_spec.get("path", "")], datatype=path_spec["datatype"]
        )
        for itf in resp[0].get("interface", []):
            for member in itf.get("lag", {}).get("member", []):
                member["name"] = str(member.get("name", "")).replace("ethernet", "et")
        res = jmespath.search(path_spec["jmespath"], resp[0])
        return {"lag": res}

    def get_es(self) -> Dict[str, Any]:
        path_spec = {
            "path": f"/system/network-instance/protocols/evpn/ethernet-segments",
            "jmespath": '"system/network-instance/protocols/evpn/ethernet-segments"."bgp-instance"[]."ethernet-segment"[].{name:name, esi:esi, "mh-mode":"multi-homing-mode",\
                oper:"oper-state",itf:interface[]."ethernet-interface"|join(\' \',@), "ni-peers":association."network-instance"[]."_ni_peers"|join(\', \',@) }',
            "datatype": "state",
        }

        def set_es_peers(resp: List[Dict[str, Any]]) -> None:
            for bgp_inst in (
                resp[0]
                .get("system/network-instance/protocols/evpn/ethernet-segments", {})
                .get("bgp-instance", [])
            ):
                for es in bgp_inst.get("ethernet-segment", []):
                    if "association" not in es:
                        es["association"] = {}
                    if "network-instance" not in es["association"]:
                        es["association"]["network-instance"] = []
                    for vrf in es["association"]["network-instance"]:
                        es_peers = (
                            vrf["bgp-instance"][0]
                            .get("computed-designated-forwarder-candidates", {})
                            .get("designated-forwarder-candidate", [])
                        )
                        vrf["_peers"] = " ".join(
                            (
                                f"{peer['address']}(DF)"
                                if peer["designated-forwarder"]
                                else peer["address"]
                            )
                            for peer in es_peers
                        )
                        vrf["_ni_peers"] = f"{vrf['name']}:[{vrf['_peers']}]"

        if (
            "evpn"
            not in self.get(paths=["/system/features"], datatype="state")[0][
                "system/features"
            ]
        ):
            return {"es": []}
        resp = self.get(
            paths=[path_spec.get("path", "")], datatype=path_spec["datatype"]
        )
        set_es_peers(resp)
        res = jmespath.search(path_spec["jmespath"], resp[0])
        return {"es": res}

    def get_arp(self) -> Dict[str, Any]:
        path_spec = {
            "path": f"/interface[name=*]/subinterface[index=*]/ipv4/arp/neighbor",
            "jmespath": '"interface"[*].subinterface[].{interface:"_subitf", NI:"_ni"|to_string(@), entries:ipv4.arp.neighbor[].{IPv4:"ipv4-address",MAC:"link-layer-address",Type:origin,expiry:"_rel_expiry" }}',
            "datatype": "state",
        }
        ni_itfs = self.get(paths=["/network-instance[name=*]"], datatype="config")
        ni_itf_map: Dict[str, List[str]] = {}
        for ni in ni_itfs[0].get("network-instance", []):
            for ni_itf in ni.get("interface", []):
                if ni_itf["name"] not in ni_itf_map:
                    ni_itf_map[ni_itf["name"]] = []
                ni_itf_map[ni_itf["name"]].append(ni["name"])
        resp = self.get(
            paths=[path_spec.get("path", "")], datatype=path_spec["datatype"]
        )
        for itf in resp[0].get("interface", []):
            for subitf in itf.get("subinterface", []):
                subitf["_subitf"] = f"{itf['name']}.{subitf['index']}"
                subitf["_ni"] = ni_itf_map.get(subitf["_subitf"], [])
                for arp_entry in (
                    subitf.get("ipv4", {}).get("arp", {}).get("neighbor", [])
                ):
                    try:
                        ts = datetime.datetime.strptime(
                            arp_entry["expiration-time"], "%Y-%m-%dT%H:%M:%S.%fZ"
                        )
                        arp_entry["_rel_expiry"] = (
                            str(ts - datetime.datetime.now()).split(".")[0] + "s"
                        )
                    except Exception:
                        arp_entry["_rel_expiry"] = "-"
        res = jmespath.search(path_spec["jmespath"], resp[0])
        return {"arp": res}

    def get_nd(self) -> Dict[str, Any]:
        path_spec = {
            "path": f"/interface[name=*]/subinterface[index=*]/ipv6/neighbor-discovery/neighbor",
            "jmespath": '"interface"[*].subinterface[].{interface:"_subitf", entries:ipv6."neighbor-discovery".neighbor[].{IPv6:"ipv6-address",MAC:"link-layer-address",State:"current-state",Type:origin,next_state:"_rel_expiry" }}',
            "datatype": "state",
        }
        resp = self.get(
            paths=[path_spec.get("path", "")], datatype=path_spec["datatype"]
        )
        for itf in resp[0].get("interface", []):
            for subitf in itf.get("subinterface", []):
                subitf["_subitf"] = f"{itf['name']}.{subitf['index']}"
                for nd_entry in (
                    subitf.get("ipv6", {})
                    .get("neighbor-discovery", {})
                    .get("neighbor", [])
                ):
                    try:
                        ts = datetime.datetime.strptime(
                            nd_entry["next-state-time"], "%Y-%m-%dT%H:%M:%S.%fZ"
                        )
                        nd_entry["_rel_expiry"] = (
                            str(ts - datetime.datetime.now()).split(".")[0] + "s"
                        )
                    except Exception:
                        nd_entry["_rel_expiry"] = "-"
        res = jmespath.search(path_spec["jmespath"], resp[0])
        return {"nd": res}
