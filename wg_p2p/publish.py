import os
import sys
import base64

import dht
import config
from log import info

def publish(conf, args):
    name = args['<name>'][0]
    lifetime = int(args['--time'])*60

    public_key = config.get_local_public_key(config.get_local_private_key(conf))
    dht.set_public_key(name, public_key, lifetime)

    public_key = base64.b64encode(public_key)
    public_key = public_key.decode('ascii')

    info('Published public key {} as "{}".', public_key, name)

