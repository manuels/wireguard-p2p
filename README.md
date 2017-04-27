WireGuard Peer-to-Peer
======================

A tool for setting up WireGuard connections from peer to peer.


Installation
------------

1) Install [BulletinBoard DHT](https://github.com/manuels/bulletinboard-dht/)

```bash
    wget 'https://github.com/manuels/bulletinboard-dht/releases/download/v0.5.0/bulletinboard_0.5.0_amd64.deb'
    sudo dpkg -i bulletinboard_0.5.0_amd64.deb
```

2) Install wg-p2p

```bash
    pip install wireguard-p2p
```

Exchange Public Keys
--------------------

1) Publish Alice's Public Key

```bash
alice$ sudo cat /etc/wireguard/bob.conf
[Interface]
ListenPort = 51800
PrivateKey = p504swpAoXHitQOOPHfPmt4qqY5ik5xkUrMnAZTr4X8=
Address = 10.0.100.2/24

alice$ wg-p2p bob publish alice
[sudo] password for alice:
Published public key LLgKTG7VaTZKzikIRR0oRkyZw1IKNPIXGt0RYJV2OWA= as "alice".
```

(Bob does the same on his machine.)

2) Retrieve Bob's Public Key

```bash
alice$ wg-p2p bob add-peer bob | sudo tee /etc/wireguard/bob.conf >/dev/null
1 peer(s) found named "alice".
Would you like to add the peer with public key EKJDRxMeLswhIpaCy6xnYLD1ZaHMNvi5SuT10L8w1m8=? [Y/n]
```

Update Bob's IP and Port
------------------------

```bash
alice$ wg-p2p bob update | sudo tee /etc/wireguard/bob.conf >/dev/null
Own public address: 38.12.81.2:21280, NAT type: Full Cone
Local NAT:  Full Cone
Remote NAT: Full Cone
[Interface]
ListenPort = 51800
PrivateKey = p504swpAoXHitQOOPHfPmt4qqY5ik5xkUrMnAZTr4X8=
Address = 10.0.100.2/24

[Peer]
AllowedIPs = 10.0.0.0/24
PublicKey = EKJDRxMeLswhIpaCy6xnYLD1ZaHMNvi5SuT10L8w1m8=
Endpoint = 81.52.9.1:2286

alice$ wg-quick up bob
```

(Bob does the same on his machine.)

