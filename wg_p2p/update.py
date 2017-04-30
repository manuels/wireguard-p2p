import os
import time
import random
import struct
import ipaddress

from base64 import b64encode, b64decode

import nacl.public

from wg_p2p.log import info, debug

import wg_p2p.dht as dht
import wg_p2p.nat as nat
import wg_p2p.config as config

nat_type_list = ['Open Internet', 'Full Cone', 'Symmetric UDP Firewall', 'Restricted Cone',
                 'Port Restricted Cone', 'Symmetric', 'Blocked']

def encode_socket_addr(nat_type, ip, port):
    ip = ipaddress.ip_address(ip)
    if type(ipaddress.IPv4Address):
        ip = '::ffff:{}.{}.{}.{}'.format(*ip.packed)
        ip = ipaddress.ip_address(ip)

    nat_type = nat_type_list.index(nat_type)

    version = b'\x01'
    return version + struct.pack('!f', time.time()) + ip.packed + struct.pack('!Hb', port, nat_type)


def encrypt(private_key, public_key, msg):
    public_key  = nacl.public.PublicKey(public_key)
    private_key = nacl.public.PrivateKey(private_key)
    box = nacl.public.Box(private_key, public_key)

    return box.encrypt(msg)


def to_peer_index(public_key_list, peer):
    try:
        i = int(peer)-1
        if i in range(len(public_key_list)):
            return i
    except ValueError:
        mached_indices = [i for i, key in enumerate(public_key_list) if key.startswith(peer)]

        if len(mached_indices) == 1:
            return mached_indices[0]
        elif len(mached_indices) == 0:
            msg = 'Peer id {} does not exist.'.format(peer)
            raise ValueError(msg)
        else:
            msg = 'Peer id {} is ambiguous.'.format(peer)
            raise ValueError(msg)
    else:
        msg = 'Peer index {} out of range ({} peers exist).'.format(peer, len(public_key_list))
        raise ValueError(msg)


def update_own_ip(private_key, public_key_list, src_port, lifetime):
    nat_type, public_ip, public_port = nat.get_ip_info(source_port=src_port)
    debug('Own public address: {}:{}, NAT type: {}'.format(public_ip, public_port, nat_type))
    local_public_key = config.get_local_public_key(private_key)

    for public_key in public_key_list:
        value = encode_socket_addr(nat_type, public_ip, public_port)
        enc_value = encrypt(private_key, public_key, value)
        dht.set_endpoint(local_public_key, public_key, enc_value, lifetime)

    return nat_type


def update_main(conf, args):
    lifetime = int(args['--time'])*60
    private_key = config.get_local_private_key(conf)
    src_port = config.get_local_port(conf)
    public_key_list = config.get_remote_public_keys(conf)

    nat_type = update_own_ip(private_key, public_key_list, src_port, lifetime)

    if len(args['<peer#>']) == 0:
        peer_list = range(len(public_key_list))
    else:
        peer_list = [ to_peer_index(public_key_list, p) for p in args['<peer#>']]

    for i in peer_list:
        conf = update_peer(conf, nat_type, private_key, public_key_list[i])

    print(conf)


def update_peer(conf, local_nat_type, private_key, remote_public_key):
    local_public_key = config.get_local_public_key(private_key)
    value_list = dht.get_endpoint(local_public_key, remote_public_key)

    pub_key = nacl.public.PublicKey(remote_public_key)
    private_key = nacl.public.PrivateKey(private_key)
    box = nacl.public.Box(private_key, pub_key)

    candidate = None
    for value in value_list:
        if len(value) != 40 + 1 + 4 + 16 + 2 + 1:
            continue

        try:
            msg = box.decrypt(bytes(value))
        except Exception as e:
            debug('Skipping DHT value:', e)
            continue

        version, t, msg, remote_nat_type = msg[:1], msg[1:5], msg[5:23], msg[23:]
        if len(msg) != 18 or version[0] != 1 or len(remote_nat_type) != 1:
            continue

        ip = ipaddress.IPv6Address(msg[:16])
        port = struct.unpack('!H', msg[16:])[0]
        if candidate is None or t > candidate[0]:
            candidate = (t, ip, port, remote_nat_type)

    if candidate is None:
        info('Peer {} not found!', b64encode(remote_public_key).decode('ascii'))
    else:
        remote_nat_type = nat_type_list[remote_nat_type[0]]

        info('Local NAT:  {}', local_nat_type)
        info('Remote NAT: {}', remote_nat_type)
        if nat_type_list.index(remote_nat_type) > nat_type_list.index('Full Cone') and \
           nat_type_list.index(local_nat_type) > nat_type_list.index('Full Cone'):
            info('!!! Connection will probably fail due to NAT type combination !!!')

        conf = config.update_endpoint(conf, remote_public_key, (ip, port))

    return conf

