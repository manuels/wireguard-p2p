# WireGuard Peer-to-Peer

A tool for setting up WireGuard connections from peer to peer.

It takes care of exchanging public keys, IP addresses and NAT traversal.

**!!! This tool has ALPHA quality. Prepare for the worst and backup /etc/wireguard !!!**


## Features

- Exchange Public Keys
- NAT-traversal and IP address exchange


## Installation

### 0) Install WireGuard
See WireGuard's [installation page](https://www.wireguard.io/install/)

### 1) Install [BulletinBoard DHT](https://github.com/manuels/bulletinboard-dht/)

```bash
    wget 'https://github.com/manuels/bulletinboard-dht/releases/download/v0.5.3/bulletinboard_0.5.3_amd64.deb'
    sudo dpkg -i bulletinboard_0.5.3_amd64.deb
```

### 2) Install wg-p2p

```bash
    pip install wireguard-p2p
```

## Exchange Public Keys

### 0) Create new config file (optional)

Alice creates a new WireGuard [configuration file](https://git.zx2c4.com/WireGuard/about/src/tools/wg.8) on her computer named `bob`. (Bob does the same on his machine.)

```bash
alice$ wg-p2p bob new | sudo tee /etc/wireguard/bob.conf >/dev/null

alice$ sudo cat /etc/wireguard/bob.conf
[Interface]
ListenPort = 51800
PrivateKey = p504swpAoXHitQOOPHfPmt4qqY5ik5xkUrMnAZTr4X8=
Address = 10.0.100.2/24
```


### 1) Publish Public Keys

Alice publishes her public key, so Bob can find it. 

```bash
alice$ wg-p2p bob publish alice
[sudo] password for alice: # to read /etc/wireguard/bob.conf
Published public key LLgKTG7VaTZKzikIRR0oRkyZw1IKNPIXGt0RYJV2OWA= as "alice".
```


### 2) Retrieve Bob's Public Key

Alice adds Bob's public key to her configuration file. (Bob does the same on his machine.)

```bash
alice$ wg-p2p bob add-peer bob | sudo tee /etc/wireguard/bob.conf >/dev/null
1 peer(s) found named "bob".
Would you like to add the peer with public key EKJDRxMeLswhIpaCy6xnYLD1ZaHMNvi5SuT10L8w1m8=? [Y/n]
```


## Exchange IP and Port with Bob and traverse NAT (daemon mode)

The daemon mode periodically looks up Bob's latest IP address and takes care about NAT traversal automatically.

Just start the daemon on Alice's and Bob's computer like this:

```bash
alice$ wg-quick up bob
alice$ wg-p2p bob daemon 1
```


## Update Bob's IP and Port and traverse NAT (manually)

Alice and Bob can determine their current IP address and setup NAT traversal (using STUN) and publish it.

This has to be done initially and from time to time when both IP addresses change or the NAT traversal expired.

```bash
alice$ wg-quick down bob

alice$ wg-p2p bob update | sudo tee /etc/wireguard/bob.conf
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

