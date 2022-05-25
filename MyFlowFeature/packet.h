#pragma once

#include "pcap.h"

typedef struct packet {
    int32  time_stamp;
    int32  microseconds;
    uint32 capture_length;
    uint16 frame_type;
    uint16 flag_segment;
    uint8  protocol;
    uint32 src_ip;
    uint32 dst_ip;
    uint16 src_port;
    uint16 dst_port;
    uint8  flags;
    uint16 window;
    uint16 payload;
} PKT;

typedef struct id {
    char forward_id[BUFSIZ];
    char backward_id[BUFSIZ];
} FLOWID;

/* functions */
PKT* getPacketInfo(FILE* fp, int* pkt_offset, PktHeader* pkt_header_t, FrameHeader* frame_header_t,
    IpHeader* ip_header_t, TcpHeader* tcp_header_t, UdpHeader* udp_header_t);

FLOWID genFlowId(PKT* pkt);