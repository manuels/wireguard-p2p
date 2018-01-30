# wireguard-p2p
A tool for setting up WireGuard connections from peer to peer.
Currently requires Rust *nightly* and [BulletinBoard](https://github.com/manuels/bulletinboard-dht/).

## Install

    $ cargo install wireguard-p2p

## Usage

    $ wireguard-p2p
    Usage: wireguard-p2p search <peer_name>
           wireguard-p2p publish <interface> <peer_name>
           wireguard-p2p daemon [--config=<path>]

### a) Exchange Public Keys

#### 1) Publish your public key

    $ wg-quick up wg0
    $ wireguard-p2p publish wg0 alices_laptop
    Publishing public key for interface 'wg0' (TEx9xzX...) as 'alices_laptop'...
    Done.

#### 2) Search for someone else's public key

    $ wireguard-p2p search bobs_laptop
    Searching for 'bobs_laptop'...
    1 public key(s) found:
      1) IoNSps5gr5Lqj+9QeY/eeZyD/oQwn7BgYz8K5SUDhwI=

### b) Initiate peer-to-peer connection

Setup your `/etc/wireguard/<dev>.conf` as usual.
Then add the remote peers for your interface to `/etc/wireguard-p2p.conf` analogous to this

    [wg0] # device name
    Peer1=IoNSps5gr5Lqj+9QeY/eeZyD/oQwn7BgYz8K5SUDhwI= # pubkey of first remote peer
    Peer2=lpRSFHf9FnjWf3DcQWioDIkXyyxHcGkNULQO2BJxOB4= # pubkey of second remote peer
    Peer3=ytS02amBxE50QhK6gFLTqoaSXHJV9NzB3TppJ/UZI0w= # pubkey of another remote peer
    ...

Start peer-to-peer connection

    $ wg-quick up wg0
    $ wireguard-p2p daemon --config=/etc/wireguard-p2p.conf
