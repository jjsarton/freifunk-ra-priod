#!/bin/sh
# priod.sh
# set ip6tables and call ra-prio

# Layout
#
#    br-client
#        AP0
#        bat0
#             mesh-vpn
#             mesh0
#
# See also:  http://ebtables.netfilter.org/br_fw_ia/br_fw_ia.html
#

IFF=br-client
start()
{
ip6tables -t mangle -I PREROUTING -m physdev --physdev-is-in -p icmpv6 --icmpv6-type router-advertisement -j NFQUEUE --queue-num 0 --queue-bypass
ip6tables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT
#/home/jj/FreiFunk/rdgwl/ra-prio &
}
stop()
{
pkill ra-prio
ip6tables -t mangle -D PREROUTING -m physdev --physdev-is-in -p icmpv6 --icmpv6-type router-advertisement -j NFQUEUE --queue-num 0 --queue-bypass
ip6tables -D FORWARD -m physdev --physdev-is-bridged -j ACCEPT

}
case $1 in
start) start;;
stop) stop;;
esac
