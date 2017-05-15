#!/bin/sh

echo "Creating group 'wg-p2p'..."
groupadd wg-p2p
echo "Creating user 'wg-p2p'..."
useradd -G wg-p2p wg-p2p

echo "Changing group of /etc/wireguard/*.conf to 'wg-p2p'...."
chgrp wg-p2p /etc/wireguard/*.conf
echo "Adjusting permissions of /etc/wireguard/*.conf to g+r..."
chmod g+r /etc/wireguard/*.conf

