# ra_priod 

Ra priod is an helper which intercept IPv6 Router Advertisement (RA) via nfqueue and process them.

This Version is a development version which will be able to work on a simulated Freifunk router on a Linux PC or on a normal node,

Some Freifunk communities use gateways which are attached via batman. Each Gateway send RA, therefore the FF-Node and the clients will send the IPv6 queries or answer to one of the gateway. The retained gateway as seen by the client is not deterministic and will often reach the target through a longer route (Traffic between the Freifunk Gateways.

Modifying the priority of the RA or dropping some of them will help to reduce the traffic between the gateways.

A further requirement for reducing the inter gateway traffic is to use different /64 prefixed for each gateway.

## How ra-priod work

Ip6tables rules are to be added so that the Router Advertisement can be intercepted and send to the user space program (ra-priod), be processed and finally be modified and put again to the stack or be dropped.

Ra-priod look at the gateway list provided by batman and compare the sender mac address with the mac address for the mac address stated within the gateway list. If the sender mac correspond to the actual retained gateway the match will be true and the RA will be processed. If the retained gateway don't provide IPv6, the RA for the gateway with the best TQ will be retained and be processed. 

Actually you can use ra-priod with 3 modes of operation:
- Set the RA priority for the best gateway to high
- Set the RA priority to low but nit for the best gateway
- Drop the RA if the gateway is not the best.

The mode can be set via command line option [-m l[ow) | -m h(igh) | -m d(rop).

Default is drop.

The expected batman interface is bat0, this can be changed by the option -b <batman interface>.

Comparison the mac addresses can be performed with 2 rules, each of them requires that the mac address of the upper interface (normally br-client), bat0 and it slaves differ only within 1 byte.

For Mode 0 the mac is build with 4 bytes prefixes followed by a byte indication the function of the interface and finally the 6. Byte correspond to the gateway number. This is useful for debugging purpose!

For mode 1 the first 5 bytes must be identical the last byte can differ for all used interfaces.

The comparison mode can be set via the option -c 0|1

RA-priod can be used within a network space while calling *batctl gwl* instead of read the debugfs file */sys/kernel/debug/batman_adv/bat0/gateways*.
