import json
import copy
import psycopg2
from psycopg2.extras import register_inet, Inet
from netaddr import IPRange, IPNetwork, IPAddress, cidr_merge
db = psycopg2.connect(
        host="0.0.0.0",
        port="5432",
        user="postgres",
        password="password",
        database="db"
        )
cur = db.cursor()

def aggregate(subnets: list):
    ranges = list(map(IPNetwork, subnets))
    ranges = cidr_merge(ranges)

with open("config.json", "r") as file:
    cfg = json.loads(file.read())

rules = []

for rule in cfg["rules"]:
    ruletext = ["--append FIREWALL"]
    match rule["rule"]:
        case "log":
            ruletext.append(f"--jump LOG")
        case "allow":
            ruletext.append(f"--jump ACCEPT")
        case "ban":
            ruletext.append(f"--jump DROP")


    if (protocol := rule["data"].get("protocol")):
        ruletext.append(f"--protocol {protocol}")
    
    if (port := rule["data"].get("port")):
        ruletext.append(f"--dport {port}")

    if rule["type"] == "raw":
        if (source := rule["data"].get("source")):
            ruletext.append(f"--source {source}")

    if rule["rule"] == "log":
        if (logprefix := rule["data"].get("log-prefix")):
            ruletext.append(f"--log-prefix \"{logprefix}\"")
        if (loglevel := rule["data"].get("log-level")):
            ruletext.append(f"--log-level {loglevel}")
    
    if rule["type"] == "raw":
        rules.append(ruletext)
        continue

    if rule["match"]["type"] == "cn":
        cur.execute("SELECT subnet FROM ipv4_cn WHERE cn=%s", (rule["match"]["data"],))
        for subnet in cur.fetchall():
            current_ruletext = copy.deepcopy(ruletext)
            current_ruletext.append(f"--source {subnet[0]}")
            rules.append(current_ruletext)


    elif rule["match"]["type"] == "asn":
            cur.execute("SELECT subnet FROM ipv4_asn WHERE asn=%s", (int(rule["match"]["data"]),))
            for subnet in cur.fetchall():
                current_ruletext = copy.deepcopy(ruletext)
                current_ruletext.append(f"--source {subnet[0]}")
                rules.append(current_ruletext)

    elif rule["match"]["type"] == "asn-handle":
            cur.execute("SELECT asn FROM asn WHERE handle=%s", (rule["match"]["data"]))
            asns = cur.fetchall()
            for asn in asns:
                cur.execute("SELECT subnet FROM ipv4_asn WHERE asn=%s", asn)
                for subnet in cur.fetchall():
                    current_ruletext = copy.deepcopy(ruletext)
                    current_ruletext.append(f"--source {subnet[0]}")
                    rules.append(current_ruletext)

with open("rules", "w+") as file:
    file.write('''
*filter

--new-chain FIREWALL
--append INPUT --jump FIREWALL
''')
    for rule in rules:
        file.write(" ".join(rule)+"\n")
    file.write("COMMIT")
