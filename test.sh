#!/bin/bash

set -v

# First we create the network namespace called "container":

ip netns delete ns1
ip netns delete ns2

ip netns add ns1
ip netns add ns2

# Next, we create a WireGuard interface in the "init" (original) namespace:

# Finally, we move that interface into the new namespace:

# Now we can configure wg0 as usual, except we specify its new namespace in doing so:

    ip link delete test1
    ip link delete test2

ip link add test1 type wireguard
ip link add test2 type wireguard

ip link set test1 netns ns1
ip link set test2 netns ns2

ip -n ns1 addr add 10.9.9.1/32 dev test1
ip -n ns2 addr add 10.9.9.2/32 dev test2

ip netns exec ns1 wg setconf test1 /etc/wireguard/test1.conf
ip netns exec ns2 wg setconf test2 /etc/wireguard/test2.conf
#ip netns exec ns1 wg-quick up test1
#ip netns exec ns2 wg-quick up test2

ip -n ns1 link set test1 up
ip -n ns2 link set test2 up

ip -n ns1 route add default dev test1
ip -n ns2 route add default dev test2

ip netns exec ns1 wg set test1 peer g912ZZMQB0REuA7brLYumd0VQS2/J/8odv7LYSm+cw0= endpoint 192.168.178.21:9991

sleep 2

ip netns exec ns1 wg
ip netns exec ns1 ping 10.9.9.2
