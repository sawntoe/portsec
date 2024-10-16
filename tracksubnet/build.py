import psycopg2
from psycopg2.extras import register_inet, Inet
import os
import json

register_inet()

db = psycopg2.connect(
        host="0.0.0.0",
        port="5432",
        user="postgres",
        password="password",
        database="db"
        )

cur = db.cursor()
cur.execute('''
DROP TABLE IF EXISTS ipv4_asn;
DROP TABLE IF EXISTS ipv6_asn;
DROP TABLE IF EXISTS ipv4_cn;
DROP TABLE IF EXISTS ipv6_cn;
DROP TABLE IF EXISTS asn;
DROP TABLE IF EXISTS cn;
CREATE TABLE ipv4_asn (asn bigint, subnet inet);
CREATE TABLE ipv6_asn (asn bigint, subnet inet);
CREATE TABLE ipv4_cn (cn varchar(2), subnet inet);
CREATE TABLE ipv6_cn (cn varchar(2), subnet inet);
CREATE TABLE asn (asn bigint, handle text, description text);
CREATE TABLE cn (cn varchar(2), name text);
''')

for asn in os.listdir("asn-ip/as/"):
    with open(os.path.join("asn-ip/as/", asn, "aggregated.json")) as file:
        data = json.loads(file.read())
        print(asn)
        cur.execute("INSERT INTO asn (asn, handle, description) VALUES (%s, %s, %s)", (int(data["asn"]), data.get("handle"), data.get("description")))
        for subnet in data["subnets"]["ipv4"]:
            cur.execute("INSERT INTO ipv4_asn (asn, subnet) VALUES (%s, %s)", (int(asn), Inet(subnet)))
        for subnet in data["subnets"]["ipv6"]:
            cur.execute("INSERT INTO ipv6_asn (asn, subnet) VALUES (%s, %s)", (int(asn), Inet(subnet)))

for cn in os.listdir("rir-ip/country/"):
    with open(os.path.join("rir-ip/country/", cn, "aggregated.json")) as file:
        data = json.loads(file.read())
        cur.execute("INSERT INTO cn (cn, name) VALUES (%s, %s)", (data["country-code"], data["country-code"]))
        for subnet in data["subnets"]["ipv4"]:
            cur.execute("INSERT INTO ipv4_cn (cn, subnet) VALUES (%s, %s)", (data["country-code"], Inet(subnet)))
        for subnet in data["subnets"]["ipv6"]:
            cur.execute("INSERT INTO ipv6_cn (cn, subnet) VALUES (%s, %s)", (data["country-code"], Inet(subnet)))

db.commit()
cur.close()
