'''
WireGuard Peer-to-Peer.

Usage:
  wg-p2p new [options]
  wg-p2p publish <conn> [options] <name>
  wg-p2p add-peer <conn> [options] <name>...
  wg-p2p update <conn> [options] [<peer#>]...
  wg-p2p daemon

Options:
  --conf=<path>        Location of WireGuard config files [default: /etc/wireguard].
  -T --time=<minutes>  Publish public key for minutes [default: 5].
  -v --verbose         Verbose output.
  -h --help            Show this screen.
  --version            Show version.
'''
from docopt import docopt

from wg_p2p.new import new
from wg_p2p.publish import publish
from wg_p2p.add_peer import add_peers
from wg_p2p.update import update_main
from wg_p2p.daemon import daemon_main

import wg_p2p.config as config

def main():
    args = docopt(__doc__, version='WireGuard Peer-to-Peer 0.1.3')

    if args['new']:
        new(args)
        return
    elif args['daemon']:
        daemon_main(args)
        return

    conn = args['<conn>']
    conf = config.read_config(args['--conf'], conn)

    if args['publish']:
        publish(conf, args)
    elif args['add-peer']:
        add_peers(conf, args)
    elif args['update']:
        update_main(conf, args)


if __name__ == '__main__':
    main()

