#pragma once

#include "packet.h"
#include <malloc.h>

typedef struct flow {
    PKT* pkt;
    struct flow * next;
} FLOW;

FLOW* createFlow(PKT* pkt);

FLOW* addPacket(FLOW* flow_head, PKT* pkt);

int isExpired(FLOW* flow_head, PKT* pkt);

double* calFeatures(FLOW* flow_head, double* features);
