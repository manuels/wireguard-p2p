#!/bin/bash
set -v

ip netns delete test1
ip netns delete test2

wg-quick up test1
wg-quick up test2

ip netns add test1
ip netns add test2

ip link set dev test1 netns test1
ip link set dev test2 netns test2

ip netns exec test1 ip addr add 10.9.9.1/24 dev test1
ip netns exec test2 ip addr add 10.9.9.2/24 dev test2

ip netns exec test1 ip link set test1 up
ip netns exec test2 ip link set test2 up
