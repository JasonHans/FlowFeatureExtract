#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "constants.h"

typedef long		    int32;
typedef unsigned long	uint32;
typedef unsigned short 	uint16;
typedef unsigned char	uint8;

/* file header */
struct pcap_file_header {
    uint32 magic;		/* 0xd4c3b2a1 */
    uint16 version_major;	/* major version 2 */
    uint16 version_minor;	/* minor version 4 */
    int32  thiszone;		/* GMT to local corrections */
    uint32 sigfigs;		/* accuracy of timestamps */
    uint32 snaplen;		/* max length saved portion of each packet */
    uint32 linktype;		/* data link type (LINKTYPE_*) */
};

/* --- common vlaue of linktype
 * 0	BSD loopback devices, except for later OpenBSD
 * 1	Ethernet, and Linux loopback devices
 * 6	802.5 Token Ring
 * 7	ARCnet
 * 8	SLIP
 * 9	PPP
 * 10	FDDI
 * 100	LLC/SNAP-encaosulated ATM
 * 101	"raw IP", with no link
 * 102	BSD/OS SLIP
 * 103	BSD/OS PPP
 * 104	Cisco HDLC
 * 105	802.11
 * 108	later OpenBSD loopback devices (with the AF_value in network byte order)
 * 113	special Linux "cooked" capture
 * 114	LocalTalk
 */

 /* packet header */
typedef struct pkt_header {
    int32  tv_sec;	/* time stamp: seconds (time_t type) */
    int32  tv_usec;	/* and microseconds */
    uint32 caplen;	/* length of portion present */
    uint32 len;		/* length of this packet (off wire) */
} PktHeader;

/* data frame header */
typedef struct frame_header {
    uint8  dst_mac[6];	// dst MAC address
    uint8  src_mac[6];	// src MAC address
    uint16 frame_type;	// frame type
} FrameHeader;

/* IP header */
typedef struct ip_header {
    uint8  version_headerlength;	// version + header length
    uint8  TOS;			// service
    uint16 total_len;		// length in bytes of header and data
    uint16 ID;			// identification
    uint16 flag_segment;	// flag + segment
    uint8  TTL;			// time to live
    uint8  protocol; 		// protocol
    uint16 check_sum;		// checksum of header
    uint32 src_ip;		// source IP address
    uint32 dst_ip;		//destination IP address
} IpHeader;

/* --- common value of protocol
 * 1	ICMP
 * 2	IGMP
 * 4	IP
 * 6	TCP
 * 8	EGP
 * 9	IGP
 * 17	UDP
 * 41	IPv6
 * 50	ESP
 * 89	OSPF
 */

 /* TCP header */
typedef struct tcp_header {
    uint16 src_port;	// source port
    uint16 dst_port;	// destination port
    uint32 seq_num;	// sequence number
    uint32 ack_num;	// acknowledge number
    uint8  header_len;	// header length (4 bit) + reserve (4 bit)
    uint8  flags;	//contorl flag
    uint16 window;	// window size
    uint16 check_sum;	//check sum of header
    uint16 urg_pointer;	//urgent pointer
} TcpHeader;

/* UDP header */
typedef struct udp_header {
    uint16 src_port;	// source port
    uint16 dst_port;	// destination port
    uint16 total_len;	//
    uint16 check_sum;	//
} UdpHeader;

/* function declaration */
void printFileHeader(struct pcap_file_header* p_hdr);
void printPktHeader(PktHeader* pkt_hdr);
void printFrameHeader(FrameHeader* fh);
void printIp(uint32 ip);
void printTcpHeader(TcpHeader* tcp_hdr);
void printUdpHeader(UdpHeader* udp_hdr);
int  readPacket(uint32 pkt_offset, FILE* fp, PktHeader* pkt_hdr, FrameHeader* frame_hdr, IpHeader* ip_hdr, TcpHeader* tcp_hdr, UdpHeader* udp_hdr);