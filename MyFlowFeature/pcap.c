#define _CRT_SECURE_NO_WARNINGS
#include "pcap.h"

char pkt_time[STRSIZE];

void printFileHeader(struct pcap_file_header* p_hdr)
{
    printf("------ Pcap File Header ------\n");
    printf("magic number: %x\n", p_hdr->magic);
    printf("version major: %u\n", p_hdr->version_major);
    printf("version minor: %u\n", p_hdr->version_minor);
    printf("thiszone: %d\n", p_hdr->thiszone);
    printf("sigfigs: %u\n", p_hdr->sigfigs);
    printf("snaplen: %u\n", p_hdr->snaplen);
    printf("linktype: %u\n", p_hdr->linktype);
}

void printPktHeader(PktHeader* pkt_hdr)
{
    long t = pkt_hdr->tv_sec;
    time_t time = (time_t)t;
    strftime(pkt_time, sizeof(pkt_time), "%Y-%m-%d %T", localtime(&time)); //get time
    printf("--- pcaket info ---\n");
    printf("time: %s\n", pkt_time);
    printf("capture length: %u\n", pkt_hdr->caplen);
    printf("len: %u\n", pkt_hdr->len);
}

int readPacket(uint32 pkt_offset, FILE* fp, PktHeader* pkt_hdr, FrameHeader* frame_hdr, IpHeader* ip_hdr, TcpHeader* tcp_hdr, UdpHeader* udp_hdr)
{
     // logic here
     // read infp of one packet
    int flag = fseek(fp, pkt_offset, SEEK_SET);
    memset(pkt_hdr, 0, sizeof(PktHeader));
    int result = 0;
    result = fread(pkt_hdr, sizeof(PktHeader), 1, fp);
    if (result != 1) {
        if (feof(fp)) {
            printf("read end of file!\n");
        }
        if (ferror(fp)) {
            printf("error read!\n");
        }
        exit(0);
    }

    memset(frame_hdr, 0, sizeof(FrameHeader));
    fread(frame_hdr, sizeof(FrameHeader), 1, fp);

    frame_hdr->frame_type = ((frame_hdr->frame_type << 8) & 0xff00) +
        ((frame_hdr->frame_type >> 8) & 0x00ff);
    if (frame_hdr->frame_type > 1500) {
        if (frame_hdr->frame_type == 0x0800) {//IP
            memset(ip_hdr, 0, sizeof(IpHeader));
            fread(ip_hdr, sizeof(IpHeader), 1, fp);

            //protocol
            switch (ip_hdr->protocol) {
            case 6: //TCP
                memset(tcp_hdr, 0, sizeof(TcpHeader));
                fread(tcp_hdr, sizeof(TcpHeader), 1, fp);
                break;
            case 17: //UDP
                memset(udp_hdr, 0, sizeof(UdpHeader));
                fread(udp_hdr, sizeof(UdpHeader), 1, fp);
                break;
            default:
                break;
            }
        }
    }
    return flag;
}