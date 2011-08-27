#ifndef __DECAP_H__
#define __DECAP_H__

#define MAX_VLAN_DEPTH 4

typedef enum {
    DPI_PROT_ETHER = 1,
    DPI_PROT_VLAN1,
    DPI_PROT_VLAN2,
    DPI_PROT_VLAN3,
    DPI_PROT_VLAN4,

    DPI_PROT_IPV4,
    DPI_PROT_IPV6,
    DPI_PROT_TCP,
    DPI_PROT_UDP,
    DPI_PROT_ICMP,

    DPI_PROT_GTP,
    DPI_PROT_GRE,
    DPI_PROT_L2TP,
    DPI_PROT_PPPOE,

    DPI_PROT_DNS,
    
    DPI_PROT_PPP,

    DPI_PROT_MPLS1,
    DPI_PROT_MPLS2,
    DPI_PROT_MPLS3,
    DPI_PROT_MPLS4,
    DPI_PROT_MPLS5,
    DPI_PROT_MPLS6,
    DPI_PROT_MPLS7,
    DPI_PROT_MPLS8,

    DPI_PROT_MAX_NUM,
} dpi_prot_type_t;

#define DPI_ETHTYPE_IPV4        0x0800
#define DPI_ETHTYPE_IPV6        0x86dd
#define DPI_ETHTYPE_ARP         0x0806
#define DPI_ETHTYPE_RARP        0x8035
#define DPI_ETHTYPE_VLAN        0x8100
#define DPI_ETHTYPE_VLAN2       0x9100
#define DPI_ETHTYPE_MPLS        0x8847
#define DPI_ETHTYPE_MPLSM       0x8848
#define DPI_ETHTYPE_PPPOED      0x8863
#define DPI_ETHTYPE_PPPOES      0x8864
#define DPI_ETHTYPE_CDMA_A10    0x8881

#define DPI_IPPROT_ICMP         1
#define DPI_IPPROT_IGMP         2
#define DPI_IPPROT_IPV4         4
#define DPI_IPPROT_TCP          6
#define DPI_IPPROT_UDP          17
#define DPI_IPPROT_IPV6         41
#define DPI_IPPROT_ROUTING      43
#define DPI_IPPROT_FRAG         44
#define DPI_IPPROT_GRE          47
#define DPI_IPPROT_ESP          50
#define DPI_IPPROT_AH           51
#define DPI_IPPROT_ICMPV6       58
#define DPI_IPPROT_IPCOMP       108
#define DPI_IPPROT_L2TP         115
#define DPI_IPPROT_MPLS         137

#define DPI_TCP_PORT_FTP        21
#define DPI_TCP_PORT_SSH        22
#define DPI_TCP_PORT_TELNET     23
#define DPI_TCP_PORT_SMTP       25
#define DPI_TCP_PORT_DNS        53
#define DPI_TCP_PORT_TFTP       69
#define DPI_TCP_PORT_HTTP       80
#define DPI_TCP_PORT_POP3       110

#define DPI_UDP_PORT_DNS        53
#define DPI_UDP_PORT_CDMA_A11   699
#define DPI_UDP_PORT_L2TP       1701
#define DPI_UDP_PORT_GTPV1_C    2123
#define DPI_UDP_PORT_GTPV1_U    2152
#define DPI_UDP_PORT_GTPV0      3386

#define DPI_PPP_IPV4            0x21
#define DPI_PPP_VJ_COMP         0x2d
#define DPI_PPP_VJ_UNCOMP       0x2f
#define DPI_PPP_IPV6            0x57
#define DPI_PPP_COMP            0xfd
#define DPI_PPP_MPLS            0x0281
#define DPI_PPP_MPLSM           0x0283
#define DPI_PPP_IPCP            0x8021
#define DPI_PPP_CCP             0x80fd
#define DPI_PPP_LCP             0xc021
#define DPI_PPP_PAP             0xc023
#define DPI_PPP_CHAP            0xc223


enum {
	IPV4_FRAGMENT,
	IPV6_FRAGMENT,
	L4_TCP,
	L4_UDP,
} state;


#endif
