import io
import os
import subprocess
import configparser

from base64 import b64encode, b64decode

from wg_p2p.utils import ip_addr_to_str

def read_config(path, conn):
    fname = os.path.basename(conn + '.conf')
    path = os.path.join(path, fname)

    proc = subprocess.run(['sudo', 'cat', path],
                          stdout=subprocess.PIPE,
                          check=True)

    return proc.stdout.decode('ascii')


def parse_config(conf):
    config = configparser.ConfigParser(strict=False)
    config.optionxform = str
    config.read_string(conf)

    return config


def get_local_private_key(conf):
    config = parse_config(conf)
    private_key = config['Interface']['PrivateKey']
    return b64decode(private_key)


def get_local_port(conf):
    config = parse_config(conf)
    port = config['Interface']['ListenPort']
    return int(port)


def get_local_public_key(private_key):
    res = subprocess.run(['wg', 'pubkey'],
                         input=b64encode(private_key),
                         stdout=subprocess.PIPE,
                         check=True)
    public_key = res.stdout.decode('ascii').strip()
    return b64decode(public_key)


def add_peer(conf, public_key):
    public_key = b64encode(public_key).decode('ascii')

    found = False
    out = ''
    for i, section in enumerate(conf.split('[Peer]')):
        if i > 0:
            section = '[Peer]' + section
        config = parse_config(section)

        if 'Peer' in config.sections():
            if config['Peer']['PublicKey'] == public_key:
                found = True

        out += section

    if not found:
        config = configparser.ConfigParser()
        config.optionxform = str
        config['Peer'] = {
            'PublicKey': public_key,
            'AllowedIPs': '10.0.0.0/24',
        }

        section = io.StringIO('\n')
        config.write(section)
        out += section.getvalue()

    return out


def update_endpoint(conf, public_key, endpoint):
    public_key = b64encode(public_key).decode('ascii')
    ip, port = endpoint
    addr = '{}:{}'.format(ip_addr_to_str(ip), port)

    out = io.StringIO()
    for i, section in enumerate(conf.split('[Peer]')):
        if i == 0:
            print(section, file=out)
            continue

        config = parse_config('[Peer]' + section)

        if config['Peer']['PublicKey'] == public_key:
            config['Peer']['Endpoint'] = addr
            config.write(out)
        else:
            print('[Peer]' + section, file=out)

    return out.getvalue()


def get_remote_public_keys(conf):
    public_key_list = []
    for section in conf.split('[Peer]')[1:]:
        config = parse_config('[Peer]' + section)

        public_key = config['Peer']['PublicKey']
        public_key = b64decode(public_key)
        public_key_list.append(public_key)

    return public_key_list

