#include "flowlist.h"
#include "constants.h"
#include <string.h>

FLOW* find(FlowList* flowlist_head, FLOWID id)
{
	FlowList* hd, * tmp;
	hd = flowlist_head;
	//if (hd->flow_id == id) {
	if((0 == strcmp(hd->flow_id.forward_id, id.forward_id)) || (0 == strcmp(hd->flow_id.forward_id, id.backward_id))) {
		return hd->flow;
	}
	else{
		while ((tmp = hd->next) != NULL) {
			//if (tmp->flow_id == id) {
			if ((0 == strcmp(tmp->flow_id.forward_id, id.forward_id)) || (0 == strcmp(tmp->flow_id.forward_id, id.backward_id))) {
				return tmp->flow;
			}
			hd = tmp;
		}
		return NULL;
	}
}

/* isInFlowList
* params:
*     head: head of flow list
*     flow_id: id of flow
* 
* returns:
*     Flow*: head of a flow
*/
FLOW* isInFlowList(FlowList* flowlist_head, FLOWID flow_id)
{
	FLOW* flow_head;
	flow_head = find(flowlist_head, flow_id);
	return flow_head;
}

FlowList* createFlowList(FLOW* flow, FLOWID* id)
{
	FlowList* head;
	head = (FlowList*)malloc(sizeof(FlowList));

	head->flow = flow;
	//head->flow_id.forward_id = id->forward_id;
	//head->flow_id.backward_id = id->backward_id;
	head->flow_id = *id;
	head->next = NULL;

	return(head);
}

FlowList* addFlow(FlowList* flowlist_head, FLOW* flow, FLOWID flow_id)
{
	FlowList* head;
	FlowList* p1, * p2;
	head = p2 = flowlist_head;
	while ((p1 = p2->next) != NULL) {
		p2 = p1;
	}
	
	FlowList* temp_fl;
	temp_fl = (FlowList*)malloc(sizeof(FlowList));

	temp_fl->flow = flow;
	//temp_fl->flow->next = flow->next;
	temp_fl->flow_id = flow_id;
	temp_fl->next = NULL;

	p2->next = temp_fl;
	return head;
}

FlowList* deleteFlow(FlowList* flowlist_head, FLOWID flow_id)
{
	FlowList* p1, * p2;

	FLOW* temp;
	FlowList* p, * pp;
	FLOW* temp1;
	
	FlowList* temp_fl1, *temp_fl2;

	if ((0 == strcmp(flowlist_head->flow_id.forward_id, flow_id.forward_id)) || (0 == strcmp(flowlist_head->flow_id.forward_id, flow_id.backward_id))) {
		p1 = flowlist_head; // free 
		p2 = flowlist_head->next;
		flowlist_head = p2;

		//free pkt
		pp = p = p1;
		free(p1->flow->pkt);
		while ((temp = p1->flow->next) != NULL) {
			free(temp->pkt);
			p1->flow = temp;
		}
		//free flow
		while (p->flow != NULL) {
			temp1 = p->flow->next;
			free(p->flow);
			p->flow = temp1;
		}
		//free flowlist		
		free(pp);

		return flowlist_head;
	}
	else{
		temp_fl1 = flowlist_head;

		while ((temp_fl2 = temp_fl1->next) != NULL) {
			/*if (*(p2->flow_id) == *flow_id) {*/
			if ((0 == strcmp(temp_fl2->flow_id.forward_id, flow_id.forward_id)) || (0 == strcmp(temp_fl2->flow_id.forward_id, flow_id.backward_id))) {
				p1 = temp_fl2; // free 
				temp_fl1->next = temp_fl2->next; //link

				//free pkt
				pp = p = p1;
				free(p1->flow->pkt);
				while ((temp = p1->flow->next) != NULL) {
					free(temp->pkt);
					p1->flow = temp;
				}
				//free flow

				while (p->flow != NULL) {
					temp1 = p->flow->next;
					free(p->flow);
					p->flow = temp1;
				}
				//free flowlist		
				free(pp);

				return flowlist_head;
			}
			else{
				printf("The flow id is not in the FlowList\n");
				return flowlist_head;
			}
			temp_fl1 = temp_fl2;
		}
	}
}
