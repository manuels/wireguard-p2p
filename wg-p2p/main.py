'''
WireGuard Peer-to-Peer.

Usage:
  wg-p2p <conn> publish [options] <name>
  wg-p2p <conn> add-peer [options] <name>...
  wg-p2p <conn> update [options] [<peer#>]...

Options:
  --conf=<path>        Location of WireGuard config files [default: /etc/wireguard].
  -T --time=<minutes>  Publish public key for minutes [default: 5].
  -v --verbose         Verbose output.
  -h --help            Show this screen.
  --version            Show version.
'''
from docopt import docopt

from publish import publish
from add_peer import add_peers
from update import update_main

import config

def main(args):
    conf = config.read_config(args['--conf'], args['<conn>'])

    if args['publish']:
        publish(conf, args)
    elif args['add-peer']:
        add_peers(conf, args)
    elif args['update']:
        update_main(conf, args)


if __name__ == '__main__':
    args = docopt(__doc__, version='WireGuard Peer-to-Peer 0.1.0')
    main(args)

