# wireguard-p2p
A tool for setting up WireGuard connections from peer to peer.
Currently requires Rust *nightly* and [BulletinBoard](https://github.com/manuels/bulletinboard-dht/).

## Usage

    $ cargo run
    Usage: wg-p2p search <peer_name>
           wg-p2p publish <interface> <peer_name>
           wg-p2p daemon [--config=<path>]

### 1) Publish your public key

    $ wg-quick up wg0
    $ cargo run publish wg0 alices_laptop
    Publishing public key for interface 'wg0' (TEx9xzX...) as 'alices_laptop'...
    Done.

### 2) Search for someone else's public key

    $ cargo run search bobs_laptop
    Searching for 'bobs_laptop'...
    1 public key(s) found:
      1) IoNSps5gr5Lqj+9QeY/eeZyD/oQwn7BgYz8K5SUDhwI=

### 3) Initiate peer-to-peer connection

Setup your `/etc/wireguard/<dev>.conf` as usual.
Then add the remote peers for your interface to `/etc/wireguard-p2p.conf` analogous to this

    [wg0] # device name
    Peer1=IoNSps5gr5Lqj+9QeY/eeZyD/oQwn7BgYz8K5SUDhwI= # pubkey of first remote peer 
    Peer2=lpRSFHf9FnjWf3DcQWioDIkXyyxHcGkNULQO2BJxOB4= # pubkey of second remote peer
    Peer3=ytS02amBxE50QhK6gFLTqoaSXHJV9NzB3TppJ/UZI0w= # pubkey of another remote peer
    ...

Start peer-to-peer connection

    $ wg-quick up wg0
    $ cargo run daemon
