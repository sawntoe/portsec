import os
import sys
import json
import socket
import atexit
import subprocess

config = json.loads(open('config.json', 'r').read())

def config_check():
    assert os.geteuid() == 0
    assert config.get("allow") or config.get("deny")
    assert not (config.get("allow") and config.get("deny"))
    assert config.get("mode") in ["passwordonly", "usernamepassword"]
    assert not (config.get("failallow") and config.get("faildeny"))
    assert config.get('failopen') != None

def get_default_iface_name_linux():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue

def startup():
    iface = get_default_iface_name_linux()
    subprocess.run(["/sbin/iptables", "--flush", "PORTSEC"], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
    subprocess.run(["/sbin/iptables", "--delete-chain", "PORTSEC"], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
    subprocess.run(["/sbin/iptables", "--flush", "WHITELIST"], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
    subprocess.run(["/sbin/iptables", "--delete-chain", "WHITELIST"], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
    subprocess.run(["/sbin/iptables", "--new-chain", "PORTSEC"])
    subprocess.run(["/sbin/iptables", "--new-chain", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "-i", iface, "--append", "INPUT", "--jump", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "-i", iface, "--append", "WHITELIST", "--protocol", "tcp", "--match", "tcp", "--dport", str(config["portsec-port"]), "--jump", "ACCEPT"])
    subprocess.run(["/sbin/iptables", "-i", iface, "--append", "PORTSEC", "--jump", config["handle_blocked"]])
    if (allowlist := config.get("allow")) != None:
        for allowrule in allowlist:
            subprocess.run(["/sbin/iptables", "-i", iface, "--append", "WHITELIST", *allowrule, "--jump", "ACCEPT"])
        subprocess.run(["/sbin/iptables", "-i", iface, "--append", "WHITELIST", "--jump", "PORTSEC"])
        return

    denylist = config["deny"]
    for denyrule in denylist:
        subprocess.run(["/sbin/iptables", "-i", iface, "--append", "WHITELIST", *denyrule, "--jump", "PORTSEC"])
    subprocess.run(["/sbin/iptables", "-i", iface, "--append", "WHITELIST", "--jump", "ACCEPT"])
    return

def cleanup():
    iface = get_default_iface_name_linux()
    subprocess.run(["/sbin/iptables", "-i", iface, "--delete", "INPUT", "--jump", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "--flush", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "--delete-chain", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "--flush", "PORTSEC"])
    subprocess.run(["/sbin/iptables", "--delete-chain", "PORTSEC"])
    if config["failopen"]:
        return
    if (allowlist := config.get("failallow")):
        for allowrule in allowlist:
            subprocess.run(["/sbin/iptables", "-i", iface, "--append", "INPUT", *allowrule, "--jump", "ACCEPT"])
        subprocess.run(["/sbin/iptables", "-i", iface, "--append", "INPUT", "--jump", config["handle_blocked"]])
    elif (denylist := config.get("faildeny")):
        for denyrule in denylist:
            subprocess.run(["/sbin/iptables", "-i", iface, "--append", "INPUT", *allowrule, "--jump", config["handle_blocked"]])
        subprocess.run(["/sbin/iptables", "-i", iface, "--append", "INPUT", "--jump", "ACCEPT"])
    else:
        subprocess.run(["/sbin/iptables", "-i", iface, "--append", "INPUT", "--jump", config["handle_blocked"]])

            

def permit_ip(ip):
    iface = get_default_iface_name_linux()
    p = subprocess.run(["/sbin/iptables", "-i", iface, "--insert", "PORTSEC", "1", "--source", ip, "--jump", "ACCEPT"])
    assert p.returncode == 0

atexit.register(cleanup)
config_check()
startup()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', config["portsec-port"]))
    s.listen()
    if config["mode"] == "usernamepassword":
        while True:
            c, addr = s.accept()
            print(f"Inbound connection from {addr}")
            c.send(b"Username: ")
            username = c.recv(1024).decode().strip()
            c.send(b"Password: ")
            password = c.recv(1024).decode().strip()
            if config["users"].get(username) == password:
                print(f"Authentication success from {addr}: (\"{username}\", \"{password}\") ")
                permit_ip(addr[0])
                c.send(b"Accepted!")
            else:
                print(f"Authentication failure from {addr}: (\"{username}\", \"{password}\") ")
            c.close()

    else:
        while True:
            c, addr = s.accept()
            print(f"Inbound connection from {addr}")
            c.send(b"Password: ")
            password = c.recv(1024).decode().strip()
            if password == config["password"]:
                print(f"Authentication success from {addr}: \"{password}\"")
                permit_ip(addr[0])
                c.send(b"Accepted!")
            else:
                print(f"Authentication failure from {addr}: \"{password}\"")
            c.close()

