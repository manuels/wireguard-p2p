import os
import sys
from base64 import b64encode, b64decode

import wg_p2p.dht
import wg_p2p.config
from wg_p2p.log import info

def add_peers(conf, args):
    for name in args['<name>']:
        conf = add(conf, name)

    print(conf)


def add(conf, name):
    value_list = dht.get_public_keys(name)
    value_list = [ v for v in value_list if len(v) == 32 ]

    if len(value_list) == 0:
        info('No peers found named "{}".', name)
        return conf
    info('{} peer(s) found named "{}".', len(value_list), name)

    value_list = [ b64encode(v) for v in value_list ]

    if len(value_list) == 1:
        selection = 0
    else:
        selection = -1
        while selection not in range(len(value_list)):
            for i, value in enumerate(value_list):
                info('{}: {}', i+1, value.decode('ascii'))
            info('Which public key would you like to use? [1-{}]', len(value_list))
            selection = input()
            
            try:
                selection = int(selection) - 1
            except ValueError:
                continue
    public_key = value_list[selection]

    msg = 'Would you like to add the peer with public key {}? [Y/n]'
    res = ' '
    while len(res) > 0 and res[0] not in 'YyNn':
        info(msg, public_key.decode('ascii'))
        res = input()
    if res.upper() == 'N':
        return conf

    return config.add_peer(conf, b64decode(public_key))

