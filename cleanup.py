import os
import subprocess

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


def cleanup():
    iface = get_default_iface_name_linux()
    subprocess.run(["/sbin/iptables", "-i", iface, "--delete", "INPUT", "--jump", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "--flush", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "--delete-chain", "WHITELIST"])
    subprocess.run(["/sbin/iptables", "--flush", "PORTSEC"])
    subprocess.run(["/sbin/iptables", "--delete-chain", "PORTSEC"])

assert os.geteuid() == 0
cleanup()
