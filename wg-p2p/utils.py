import ipaddress

def ip_addr_to_str(ip):
    if type(ip) == ipaddress.IPv4Address:
        return str(ip)
    elif ip.exploded.startswith('0000:0000:0000:0000:0000:ffff:'):
        return str(ipaddress.ip_address(ip.packed[-4:]))
    else:
        return '[{}]'.format(ip)

