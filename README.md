# AttackServices
The Minary GUI's primary task is to display information and act as a host for extensions. 
It does not posses the capabilities to attack systems. Instead the attacking part is conducted by the _AttackServices_ which
are loaded into the Minary GUI during its initialization phase.

Minary contains the following attack services:
  * **APE**: Poison target system's ARP cache in an IPv4 network
  * **Sniffer**: Read victim system's data from the "wire"
  * **HttpReverseProxy**: Rogue HTTP(S) server to read/manipulate/attack client system's web traffic

The following attack services are planned:
  * **Rogue DHCPv4**: A rogue DHCP server to answer client DHCP requests in an IPv4 network
  * **Rogue DHCPv6**: A rogue DHCP server to answer client DHCP requests in an IPv6 network
  * **IPv6 NDP**: Poison target system's neighbor cache in an IPv6 network
  
