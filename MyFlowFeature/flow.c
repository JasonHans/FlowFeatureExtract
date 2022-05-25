#include "flow.h"
#include <math.h>

FLOW* createFlow(PKT* pkt)
{
    FLOW* flow;
    flow = (FLOW*)malloc(sizeof(FLOW));
    //
    flow->pkt = pkt;
    flow->next = NULL;
    return flow;
}

int isExpired(FLOW* packet_head, PKT* pkt)
{
    FLOW* tmp, * p1;
    p1 = packet_head;
    while ((tmp = p1->next) != NULL) {
        p1 = tmp;
    }
    if (pkt->time_stamp - p1->pkt->time_stamp > EXPIRED_TIME) {
        return 1; //expired
    }
    else {
        return 0; //not expired
    }
}

FLOW* addPacket(FLOW* packet_head, PKT* pkt)
{
    FLOW* head;
    FLOW* p1, * p2;

    head = p2 = packet_head;
    while ((p1 = p2->next) != NULL) {
        p2 = p1;
    }

    FLOW* temp_packet;
    temp_packet = (FLOW*)malloc(sizeof(FLOW));
   
    temp_packet->pkt = pkt;
    temp_packet->next = NULL;

    p2->next = temp_packet;

    return head;
}


/* compute features */
double* calFeatures(FLOW* flow, double* features)
{

        //double features[21];

        FLOW* head, * p1, * p2;
        head = p1 = flow;

        if (p1 != NULL && p1->next != NULL) {//at least 2 packets
            /* f0: flow_duration */
            double flow_duration = 0;

            double start_timestamp;
            double latest_timestamp;

            start_timestamp = (double)p1->pkt->time_stamp + ((double)p1->pkt->microseconds / 1000000);

            //printf("start time: %f\n", start_timestamp);


            /* f1: bytes/s */
            double flow_bytes_s = 0;
            /* f2: packets/s */
            double flow_packet_s = 0;
            /* f3: total bytes */
            double total_bytes = 0;
            /* f4: total packets */

            double count = 0;

            /* f5: packet_bytes_min */
            double packet_bytes_min = 0;
            /* f6: packet_bytes_max */
            double packet_bytes_max = 0;
            packet_bytes_min = (double)p1->pkt->capture_length;
            packet_bytes_max = (double)p1->pkt->capture_length;

            /* packet bytes mean */
            double packet_bytes_mean = 0;
            /* packet time min max mean std*/
            double packet_time_min = 864000;
            double packet_time_max = 0;
            double packet_time_mean = 0;
            double packet_time_std = 0;

            /* control flag */
            double num_psh_flag = 0;
            double num_urg_flag = 0;
            double num_fin_flag = 0;
            double num_syn_flag = 0;
            double num_rst_flag = 0;
            double num_ack_flag = 0;
            double num_cwr_flag = 0;
            double num_ece_flag = 0;

            while (p1 != NULL) {
                count++;

                total_bytes += (double)p1->pkt->capture_length;

                if ((double)p1->pkt->capture_length < packet_bytes_min) {
                    packet_bytes_min = (double)p1->pkt->capture_length;
                }
                if ((double)p1->pkt->capture_length > packet_bytes_max) {
                    packet_bytes_max = (double)p1->pkt->capture_length;
                }

                num_fin_flag = num_fin_flag + (double)((p1->pkt->flags)      & 0x01);
                num_syn_flag = num_syn_flag + (double)((p1->pkt->flags >> 1) & 0x01);
                num_rst_flag = num_rst_flag + (double)((p1->pkt->flags >> 2) & 0x01);
                num_psh_flag = num_psh_flag + (double)((p1->pkt->flags >> 3) & 0x01);
                num_ack_flag = num_ack_flag + (double)((p1->pkt->flags >> 4) & 0x01);
                num_urg_flag = num_urg_flag + (double)((p1->pkt->flags >> 5) & 0x01);
                num_ece_flag = num_ece_flag + (double)((p1->pkt->flags >> 6) & 0x01);
                num_cwr_flag = num_cwr_flag + (double)((p1->pkt->flags >> 7) & 0x01);
                
                p2 = p1->next;
                if (p2 != NULL) {
                    if (packet_time_min > (double)p2->pkt->time_stamp + (double)p2->pkt->microseconds / 1000000 - 
                        ((double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000)) {
                        packet_time_min = (double)p2->pkt->time_stamp + (double)p2->pkt->microseconds / 1000000 - 
                            ((double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000);
                    }
                    if (packet_time_max < (double)p2->pkt->time_stamp + (double)p2->pkt->microseconds / 1000000 - 
                        ((double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000)) {
                        packet_time_max = (double)p2->pkt->time_stamp + (double)p2->pkt->microseconds / 1000000 -
                            ((double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000);
                    }
                }
                p1 = p2;
            }

            p1 = head;
            while ((p2 = p1->next) != NULL) {
                p1 = p2;
            }

            latest_timestamp = (double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000;

            //printf("end time: %f\n", latest_timestamp);

            flow_duration = latest_timestamp - start_timestamp;
            features[0] = flow_duration;

            /* f1: bytes/s */
            flow_bytes_s = total_bytes / flow_duration;
            features[1] = flow_bytes_s;

            flow_packet_s = count / flow_duration;
            features[2] = flow_packet_s;

            features[3] = total_bytes;

            features[4] = count;

            features[5] = packet_bytes_min;
            features[6] = packet_bytes_max;

            packet_bytes_mean = total_bytes / count;
            features[7] = packet_bytes_mean;

            /* pcaket bytes std */
            double packet_bytes_std = 0, sum = 0;
            p1 = flow;
            while (p1 != NULL) {
                sum = sum + (((double)p1->pkt->capture_length - packet_bytes_mean)) * 
                    (((double)p1->pkt->capture_length - packet_bytes_mean));
                p2 = p1->next;
                p1 = p2;
            }
            packet_bytes_std = sqrt(sum / count);
            features[8] = packet_bytes_std;

            features[9] = packet_time_min;
            features[10] = packet_time_max;
            packet_time_mean = flow_duration / (count - 1);
            features[11] = packet_time_mean;
            p1 = flow;
            sum = 0;
            while (p1 != NULL) {
                if ((p2 = p1->next) != NULL) {
                    sum = sum + ((double)p2->pkt->time_stamp + (double)p2->pkt->microseconds / 1000000 -
                        ((double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000) - packet_time_mean)*
                        ((double)p2->pkt->time_stamp + (double)p2->pkt->microseconds / 1000000 -
                            ((double)p1->pkt->time_stamp + (double)p1->pkt->microseconds / 1000000) - packet_time_mean);
                }
                p1 = p2;
            }
            packet_time_std = sqrt(sum / (count - 1));
            features[12] = packet_time_std;

            features[13] = num_psh_flag;
            features[14] = num_urg_flag;
            features[15] = num_fin_flag;
            features[16] = num_syn_flag;
            features[17] = num_rst_flag;
            features[18] = num_ack_flag;
            features[19] = num_cwr_flag;
            features[20] = num_ece_flag;
        }
        return features;
}