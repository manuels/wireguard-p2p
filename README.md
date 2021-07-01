Exchanges your IP via a OpenDHT.

Just run `wg-quick up wg0` and then `sudo wireguard-p2p` on both peers.
wireguard-p2p will determine your current public IP, exchange it via OpenDHT, set the endpoint to a localhost port and proxy packages between both peers.


## Install
```bash
cargo install wireguard-p2p
```

## Dependencies

### OpenDHT
OpenDHT will have to be discoverable by pkgconfig

Follow the build/install instructions [here](https://github.com/savoirfairelinux/opendht/wiki/Build-the-library#using-cmake)

### Fedora
```bash
sudo dnf install -y jsoncpp-devel http-parser-devel
```
