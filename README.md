# WireGuard Peer-to-Peer

This code is unstable, has not been reviewed and might leak your private keys (I hope not, though).

A program that manages p2p endpoints for WireGuard devices

It contains of two tools:

 - wg-p2p handles endpoint configuration to other wg-p2p clients
 - wg-exchange simplifies the exchange of public keys

## How to Use

    # setup wireguard interface
    sudo wg-quick up wg0
    # start client
    sudo RUST_LOG=wg_p2p wg-p2p -i wg0

# Requirements

  - rust nightly
  - opendht
  - wireguard
