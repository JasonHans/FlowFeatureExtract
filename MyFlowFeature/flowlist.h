#pragma once
#include <stdio.h>
#include "packet.h"
#include "flow.h"

typedef struct flowlist {
    FLOW* flow;
    FLOWID flow_id;
    struct flowlist* next;
} FlowList;

/* function */
FlowList* createFlowList(FLOW* flow, FLOWID* id);

FLOW* find(FlowList* flowlist_head, FLOWID id);

FLOW* isInFlowList(FlowList* flowlist_head, FLOWID flow_id);

FlowList* addFlow(FlowList* flowlist_head, FLOW* flow, FLOWID flow_id);

FlowList* deleteFlow(FlowList* flowlist_head, FLOWID flow_id);


