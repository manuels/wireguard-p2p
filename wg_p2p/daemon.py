import time
import base64
import socket
import functools
import ipaddress
import selectors
import subprocess
import collections
import configparser
import multiprocessing as mp
import multiprocessing.managers

import wg_p2p.dht as dht
import wg_p2p.config as config
import wg_p2p.update as update
import wg_p2p.nat as nat
from wg_p2p.multiplexer import Multiplexer

def fork(f):
    @functools.wraps(f)
    def wrapper(*args, **kwds):
        p = mp.Process(target=f, args=args)
        p.start()
        return p
    return wrapper


def get_current_endpoint(conn, public_key):
    public_key = base64.b64encode(public_key).decode('ascii')

    cmd = ['sudo', 'wg', 'show', conn, 'endpoints']
    res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)

    for line in res.stdout.decode('ascii').split('\n'):
        if line.startswith(public_key):
            return line.split('\t')[1]
    return None


@fork
def fork_dht_lookup(conn, multiplexer, private_key, local_public_key, remote_public_key):
    while True:
        endpoint = update.get_endpoint(private_key, local_public_key, remote_public_key)

        if endpoint is None:
            print('No Endpoint found in DHT.')
            time.sleep(15)
            continue

        ep_ip, ep_port, ep_nat_type = endpoint
        mplexed_addr = multiplexer.register((str(ep_ip), ep_port))

        peer = base64.b64encode(remote_public_key).decode('ascii')
        mplexed = '{}:{}'.format(*mplexed_addr)

        curr_endpoint = get_current_endpoint(conn, remote_public_key)
        if curr_endpoint is not None and curr_endpoint != mplexed:
            cmd = ['sudo', 'wg', 'set', conn, 'peer', peer, 'endpoint', mplexed]
            print(cmd)
            subprocess.run(cmd, check=True)

        print('Endpoint {}:{} ({}) found in DHT.'.format(*endpoint[:2], mplexed))
        time.sleep(60)


@fork
def fork_nat_traversal(private_key, local_public_key, remote_public_key, stun_server_list, nat_port):
    import wg_p2p.nat as nat

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', nat_port))

        for stun_host, stun_port in stun_server_list:
            nat_type, res = nat.get_nat_type(sock, '127.0.0.1', source_port=nat_port, stun_host=stun_host, stun_port=stun_port)
            if nat_type != 'Blocked':
                break
        sock.close()

        if nat_type == 'Blocked':
            print('NAT type: Blocked!')
            time.sleep(15)
            continue

        external_ip = res['ExternalIP']
        external_port = res['ExternalPort']

        print('Publishing own address: {}:{} (127.0.0.1:{}).'.format(external_ip, external_port, nat_port))
        value = update.encode_socket_addr(nat_type, external_ip, external_port)
        enc_value = update.encrypt(private_key, remote_public_key, value)
        dht.set_endpoint(local_public_key, remote_public_key, enc_value, 5*60)

        time.sleep(60)


class MyManager(mp.managers.BaseManager):
    pass

def daemon_main(args):
    cfg = configparser.ConfigParser()
    cfg.read('/etc/wireguard-p2p.conf')

    processes = []

    for conn in cfg.sections():
        conf = config.read_config(args['--conf'], conn)

        if cfg[conn]['Peers'] == 'all':
            peers = config.get_remote_public_keys(conf)
        else:
            peers = cfg[conn]['Peers']

        for i, p in enumerate(peers):
            processes.append(daemon(conn, conf, p, i))

    for p in processes:
        p.join()


@fork
def daemon(conn, conf, remote_public_key, i):
    wg_port = config.get_local_port(conf)
    proxy_port = wg_port + 2*i + 1
    nat_port = wg_port + 2*i + 2

    private_key = config.get_local_private_key(conf)
    local_public_key = config.get_local_public_key(private_key)
    public_key_list = config.get_remote_public_keys(conf)

    MyManager.register('Multiplexer', Multiplexer)
    mgr = MyManager()
    mgr.start()
    multiplexer = mgr.Multiplexer(proxy_port, [wg_port, nat_port])

    i = update.to_peer_index(public_key_list, remote_public_key)
    endpoint = config.get_endpoint(conf, i)
    multiplexer.register(endpoint)
    
    fork_dht_lookup(conn, multiplexer, private_key, local_public_key, remote_public_key)

    stun_port = nat.DEFAULTS['stun_port']
    stun_servers = [ multiplexer.register((server,stun_port))
                     for server in nat.stun_servers_list ]

    public_address = fork_nat_traversal(private_key, local_public_key, remote_public_key,
                                        stun_servers, nat_port)

    while True:
        multiplexer.multiplex()
