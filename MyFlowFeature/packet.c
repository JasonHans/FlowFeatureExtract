#define _CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "packet.h"
#include <string.h>

/* --- get each packet infomation ---
 * params:
 *     FILE *fp: the pcap file
 *     int* pkt_offset: offset of packet
 *     PacketInfo* pkt: variable of packet
 *     pkt_header_t, ... , udp_header_t: variables of pcap parts
 * return:
 *     0: not end of pcap file
 *     1: end of pcap file
 */
PKT* getPacketInfo(FILE* fp, int *pkt_offset, PktHeader* pkt_header_t, FrameHeader* frame_header_t,
	IpHeader* ip_header_t, TcpHeader* tcp_header_t, UdpHeader* udp_header_t)
{
	PKT* pkt;
	pkt = (PKT*)malloc(sizeof(PKT));

	fseek(fp, *pkt_offset, SEEK_SET);
	memset(pkt_header_t, 0, sizeof(PktHeader));
	fread(pkt_header_t, sizeof(PktHeader), 1, fp);
	pkt->time_stamp = pkt_header_t->tv_sec;
	pkt->microseconds = pkt_header_t->tv_usec;
	pkt->capture_length = pkt_header_t->caplen;

	*pkt_offset = *pkt_offset + sizeof(PktHeader) + pkt_header_t->caplen;

	memset(frame_header_t, 0, sizeof(FrameHeader));
	fread(frame_header_t, sizeof(FrameHeader), 1, fp);
	pkt->frame_type = ((frame_header_t->frame_type << 8) & 0xff00) + ((frame_header_t->frame_type >> 8) & 0x00ff);
	if (pkt->frame_type > 1500) {
		if (pkt->frame_type == 0x0800) {
			memset(ip_header_t, 0, sizeof(IpHeader));
			fread(ip_header_t, sizeof(IpHeader), 1, fp);
			pkt->flag_segment = ((ip_header_t->flag_segment << 8) & 0xff00) + ((ip_header_t->flag_segment >> 8) & 0x00ff);
			pkt->src_ip = ((ip_header_t->src_ip >> 24) & 0x000000ff) + ((ip_header_t->src_ip >> 8) & 0x0000ff00) +
				((ip_header_t->src_ip << 8) & 0x00ff0000) + ((ip_header_t->src_ip << 24) & 0xff000000);
			pkt->dst_ip = ((ip_header_t->dst_ip >> 24) & 0x000000ff) + ((ip_header_t->dst_ip >> 8) & 0x0000ff00) +
				((ip_header_t->dst_ip << 8) & 0x00ff0000) + ((ip_header_t->dst_ip << 24) & 0xff000000);
			switch (ip_header_t->protocol) {
			case 6:
				pkt->protocol = ip_header_t->protocol;
				memset(tcp_header_t, 0, sizeof(TcpHeader));
				fread(tcp_header_t, sizeof(TcpHeader), 1, fp);
				pkt->src_port = ((tcp_header_t->src_port << 8) & 0xff00) + ((tcp_header_t->src_port >> 8) & 0x00ff);
				pkt->dst_port = ((tcp_header_t->dst_port << 8) & 0xff00) + ((tcp_header_t->dst_port >> 8) & 0x00ff);
				pkt->flags = tcp_header_t->flags;
				pkt->window = ((tcp_header_t->window << 8) & 0xff00) + ((tcp_header_t->window >> 8) & 0x00ff);
				pkt->payload = pkt->capture_length - sizeof(FrameHeader) - sizeof(IpHeader) - sizeof(TcpHeader);
				break;
			case 17:
				memset(udp_header_t, 0, sizeof(UdpHeader));
				fread(udp_header_t, sizeof(UdpHeader), 1, fp);
				pkt->src_port = ((udp_header_t->src_port << 8) & 0xff00) + ((udp_header_t->src_port >> 8) & 0x00ff);
				pkt->dst_port = ((udp_header_t->dst_port << 8) & 0xff00) + ((udp_header_t->dst_port >> 8) & 0x00ff);
				pkt->flags = 0x00;
				pkt->window = 0x00000;
				pkt->payload = pkt->capture_length - sizeof(FrameHeader) - sizeof(IpHeader) - sizeof(UdpHeader);
				break;
			default:
				break;
			}
		}
	}
	return pkt;
}

/* --- generate flow ID ---
 * params:
 *     PacketInfo* pkt: a packet
 *
 * return:
 *     char* flow_id: Id of a packet
 */
FLOWID genFlowId(PKT* pkt)
{
	FLOWID flow_id;
	char buf_f[STRSIZE];
	char buf_b[STRSIZE];
	sprintf(buf_f, "%x-%x-%x-%x-%x", pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, pkt->protocol);
	sprintf(buf_b, "%x-%x-%x-%x-%x", pkt->dst_ip, pkt->dst_port, pkt->src_ip, pkt->src_port, pkt->protocol);
	//flow_id.forward_id = buf_f;
	//flow_id.backward_id = buf_b;
	strcpy(flow_id.forward_id, buf_f);
	strcpy(flow_id.backward_id, buf_b);
	return flow_id;
}
