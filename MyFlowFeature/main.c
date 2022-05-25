#define _CRT_SECURE_NO_WARNINGS
#include "flowlist.h"
#include <string.h>

void genFeatureCsv(char* pcap_file, char* csv_file);

int main()
{
	genFeatureCsv("./testdata/test.pcap",	"./testdata/features.csv");
	
	return 0;
}



void genFeatureCsv(char* pcap_file, char* csv_file) {

	FILE* fp;
	//open file
	if ((fp = fopen(pcap_file, "rb")) == NULL) {
		printf("error: can not open pcap file!\n");
		exit(0);
	}

	FILE* fout;
	//fout = fopen(csv_file, "w");
	fout = fopen(csv_file, "a+");

	//struct pcap_file_header* file_header_t;
	PktHeader* pkt_header_t;
	FrameHeader* frame_header_t;
	IpHeader* ip_header_t;
	TcpHeader* tcp_header_t;
	UdpHeader* udp_header_t;
	//file_header_t  = (struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
	pkt_header_t = (PktHeader*)malloc(sizeof(PktHeader));
	frame_header_t = (FrameHeader*)malloc(sizeof(FrameHeader));
	ip_header_t = (IpHeader*)malloc(sizeof(IpHeader));
	tcp_header_t = (TcpHeader*)malloc(sizeof(TcpHeader));
	udp_header_t = (UdpHeader*)malloc(sizeof(UdpHeader));

	long* pkt_offset;
	pkt_offset = (long*)malloc(sizeof(long));
	*pkt_offset = sizeof(struct pcap_file_header);
	//printf("%d", *pkt_offset);

	int   ip_len, http_len, ip_protocol;
	int   src_port, dst_port, tcp_flags;
	char  buf[BUFSIZ];
	char  src_ip[STRSIZE], dst_ip[STRSIZE];

	char sip[16];
	char dip[16];
	
	char header[68][26] = { {"src ip"}, {"src port"}, {"dst ip"}, {"dst port"}, {"protocol"}, {"flow duration"},
	{"flow bytes/s"}, {"flow packet/s"}, {"total bytes"}, {"packet num"}, {"packet bytes min"},
	{"packet bytes max"}, {"packet bytes mean"}, {"packet bytes std"}, {"packet time min"},
	{"packet time max"}, {"packet time mean"}, {"packet time std"}, {"num psh flag"}, {"num urg flag"},
	{"num fin flag"}, {"num syn flag"}, {"num rst flag"}, {"num ack flag"}, {"num cwr flag"},
	{"num ece flag"}, 
	{"forward flow duration"}, {"forward flow bytes/s"}, {"forward flow packet/s"}, {"forward total bytes"}, 
	{"forward packet num"},	{"forward packet bytes min"}, {"forward packet bytes max"}, {"forward packet bytes mean"},
	{"forward packet bytes std"}, {"forward packet time min"}, {"forward packet time max"}, 
	{"forward packet time mean"}, {"forward packet time std"}, {"forward num psh flag"}, {"forward num urg flag"}, 	
	{"forward num fin flag"}, {"forward num syn flag"}, {"forward num rst flag"}, {"forward num ack flag"}, 
	{"forward num cwr flag"}, {"forward num ece flag"}, 
	{"backward flow duration"}, {"backward flow bytes/s"}, {"backward flow packet/s"}, {"backward total bytes"}, 
	{"backward packet num"}, {"backward packet bytes min"}, {"backward packet bytes max"}, 
	{"backward packet bytes mean"}, {"backward packet bytes std"}, {"backward packet time min"}, 
	{"backward packet time max"}, {"backward packet time mean"}, {"backward packet time std"}, 
	{"backward num psh flag"}, {"backward num urg flag"}, {"backward num fin flag"}, {"backward num syn flag"}, 
	{"backward num rst flag"}, {"backward num ack flag"}, {"backward num cwr flag"}, {"backward num ece flag"} };
	for (int i = 0;i < 68;i++) {
		fprintf(fout, "%s", header[i]);
		fprintf(fout, "%s", ",");
	}
	fprintf(fout, "%s", "\n");

	double* features;
	features = (double*)malloc(sizeof(double) * 21);
	double* p_features;

	fseek(fp, 0, SEEK_END);		//将文件指针移动文件结尾
	long file_size = ftell(fp);	//求出当前文件指针距离文件开始的字节数
	//printf("size of file is %d", file_size);

	//add logic here
	/* create (initialize) flow and flow_list */
	PKT* pkt;
	pkt = getPacketInfo(fp, pkt_offset, pkt_header_t, frame_header_t, ip_header_t, tcp_header_t, udp_header_t);

	//create flow
	FLOW* flow = createFlow(pkt);
	printf("flow created!!!\n");

	//get flow id
	FLOWID flow_id = genFlowId(pkt);

	//create flowlist
	FlowList* flow_list = createFlowList(flow, &flow_id);
	printf("flowlist created!!!\n");
	printf("forward_id: %s\n", flow_id.forward_id);
	printf("backward_id: %s\n", flow_id.backward_id);

	//judge flow and compute features
	FLOW* found_head;

	int pkt_num = 1;

	/*while (*pkt_offset != file_size) {*/
	//while (fseek(fp, *pkt_offset, SEEK_SET) == 0) {
	while (feof(fp)==0) {

		printf("position: %d / %d\n", *pkt_offset, file_size);

		pkt = getPacketInfo(fp, pkt_offset, pkt_header_t, frame_header_t, ip_header_t, tcp_header_t, udp_header_t);
		pkt_num++;
		printf("packet %d arrive!!!\n", pkt_num);
		if ((pkt->protocol != 6) && (pkt->protocol != 17)) {
			printf("packet %d is not TCP and UDP!!!\n", pkt_num);
			continue;
		}
		printf("packet %d is TCP or UDP!!!\n", pkt_num);
		flow_id = genFlowId(pkt, flow_id);
		if ((found_head = isInFlowList(flow_list, flow_id)) != NULL) {//is in flow
			printf("packet %d is in flow\n", pkt_num);
			//expired?
			if (isExpired(found_head, pkt)==0) {//no

				//FIN?
				if (1 == ((found_head->pkt->flags) & 0x01)) {
					addPacket(found_head, pkt);
					//calculate feetures and free


					//create forward and backward flow, and calculate features
					FLOW* temp_h1, * temp_h2;
					temp_h1 = found_head;
					int forward_num = 0;
					int backward_num = 0;

					FLOW* forward_flow;
					forward_flow = NULL;
					FLOW* backward_flow;
					backward_flow = NULL;

					while (temp_h1 != NULL) {// split into forward and backward flow

						FLOWID id = genFlowId(temp_h1->pkt);
						if (0 == strcmp(id.forward_id, flow_id.forward_id)) { //forward
							forward_num++;
							if (1 == forward_num) { //create forward flow list
								forward_flow = createFlow(temp_h1->pkt);
								//forward_list = createFlowList(forward_flow, &flow_id);
							}
							else {// add pkt to forward flow list
								addPacket(forward_flow, temp_h1->pkt);
							}
						}
						if (0 == strcmp(id.forward_id, flow_id.backward_id)) {// backward
							backward_num++;
							if (1 == backward_num) {
								backward_flow = createFlow(temp_h1->pkt);
							}
							else
							{
								addPacket(backward_flow, temp_h1->pkt);
							}
						}
						temp_h2 = temp_h1->next;
						temp_h1 = temp_h2;
					}


					//calculate features
					printf("calculate features\n");
					calFeatures(found_head, features);

					sprintf(sip, "%d.%d.%d.%d", (found_head->pkt->src_ip >> 24) & 0x000000ff,
						(found_head->pkt->src_ip) >> 16 & 0x000000ff, (found_head->pkt->src_ip >> 8) & 0x000000ff,
						found_head->pkt->src_ip & 0x000000ff);
					fprintf(fout, "%s", sip);
					fprintf(fout, "%s", ",");
					fprintf(fout, "%d", found_head->pkt->src_port);
					fprintf(fout, "%s", ",");
					sprintf(dip, "%d.%d.%d.%d", (found_head->pkt->dst_ip >> 24) & 0x000000ff,
						(found_head->pkt->dst_ip) >> 16 & 0x000000ff, (found_head->pkt->dst_ip >> 8) & 0x000000ff,
						found_head->pkt->dst_ip & 0x000000ff);
					fprintf(fout, "%s", dip);
					fprintf(fout, "%s", ",");
					fprintf(fout, "%d", found_head->pkt->dst_port);
					fprintf(fout, "%s", ",");
					fprintf(fout, "%d", found_head->pkt->protocol);
					fprintf(fout, "%s", ",");

					//save features
					for (p_features = features; p_features < features + 21; p_features++) {
						//fwrite(p_features, sizeof(float), 1, fout);
						//fwrite(",", sizeof(char), 1, fout);
						fprintf(fout, "%f", *p_features);
						fprintf(fout, "%s", ",");
					}

					calFeatures(forward_flow, features);
					for (p_features = features; p_features < features + 21; p_features++) {
						//fwrite(p_features, sizeof(float), 1, fout);
						//fwrite(",", sizeof(char), 1, fout);
						fprintf(fout, "%f", *p_features);
						fprintf(fout, "%s", ",");
					}
					calFeatures(backward_flow, features);
					for (p_features = features; p_features < features + 21; p_features++) {
						//fwrite(p_features, sizeof(float), 1, fout);
						//fwrite(",", sizeof(char), 1, fout);
						fprintf(fout, "%f", *p_features);
						fprintf(fout, "%s", ",");
					}
					fprintf(fout, "%s", "\n");

					printf("features saved\n");

					//delete expired flow
					flow_list = deleteFlow(flow_list, flow_id);
					printf("expired flow deteleted\n");
					//delete f and b flow
					FLOW* f_1, * f_2;
					f_1 = forward_flow;
					while (f_1 != NULL) {
						f_2 = f_1->next;
						free(f_1);
						f_1 = NULL;
						f_1 = f_2;
					}
					f_1 = backward_flow;
					while (f_1 != NULL) {
						f_2 = f_1->next;
						free(f_1);
						f_1 = NULL;
						f_1 = f_2;
					}

				}
				else
				{
					printf("packet %d is not expired\n", pkt_num);
					//add to flow
					addPacket(found_head, pkt);
					printf("packet %d added!!!\n", pkt_num);
				}
			}
			else {//yes
				printf("packet %d expired\n", pkt_num);
				//only one packet?
				if (found_head->next == NULL) {
					//delete flow
					flow_list = deleteFlow(flow_list, flow_id);
				}
				else
				{
					//create forward and backward flow, and calculate features
					FLOW* temp_h1, * temp_h2;
					temp_h1 = found_head;
					int forward_num = 0;
					int backward_num = 0;

					FLOW* forward_flow;
					forward_flow = NULL;
					FLOW* backward_flow;
					backward_flow = NULL;

					while (temp_h1 != NULL) {// split into forward and backward flow
						

						FLOWID id = genFlowId(temp_h1->pkt);
						if (0 == strcmp(id.forward_id, flow_id.forward_id)) { //forward
							forward_num++;
							if (1 == forward_num) { //create forward flow list
								forward_flow = createFlow(temp_h1->pkt);
								//forward_list = createFlowList(forward_flow, &flow_id);
							}
							else {// add pkt to forward flow list
								addPacket(forward_flow, temp_h1->pkt);
							}
						}
						if (0 == strcmp(id.forward_id, flow_id.backward_id)) {// backward
							backward_num++;
							if (1 == backward_num) {
								backward_flow = createFlow(temp_h1->pkt);
							}
							else
							{
								addPacket(backward_flow, temp_h1->pkt);
							}
						}
						temp_h2 = temp_h1->next;
						temp_h1 = temp_h2;
					}


					//calculate features
					printf("calculate features\n");
					calFeatures(found_head, features);

					sprintf(sip, "%d.%d.%d.%d", (found_head->pkt->src_ip >> 24) & 0x000000ff,
						(found_head->pkt->src_ip) >> 16 & 0x000000ff, (found_head->pkt->src_ip >> 8) & 0x000000ff,
						found_head->pkt->src_ip & 0x000000ff);
					fprintf(fout, "%s", sip);
					fprintf(fout, "%s", ",");
					fprintf(fout, "%d", found_head->pkt->src_port);
					fprintf(fout, "%s", ",");
					sprintf(dip, "%d.%d.%d.%d", (found_head->pkt->dst_ip >> 24) & 0x000000ff,
						(found_head->pkt->dst_ip) >> 16 & 0x000000ff, (found_head->pkt->dst_ip >> 8) & 0x000000ff,
						found_head->pkt->dst_ip & 0x000000ff);
					fprintf(fout, "%s", dip);
					fprintf(fout, "%s", ",");
					fprintf(fout, "%d", found_head->pkt->dst_port);
					fprintf(fout, "%s", ",");
					fprintf(fout, "%d", found_head->pkt->protocol);
					fprintf(fout, "%s", ",");

					//save features
					for (p_features = features; p_features < features + 21; p_features++) {
						//fwrite(p_features, sizeof(float), 1, fout);
						//fwrite(",", sizeof(char), 1, fout);
						fprintf(fout, "%f", *p_features);
						fprintf(fout, "%s", ",");
					}

					calFeatures(forward_flow, features);
					for (p_features = features; p_features < features + 21; p_features++) {
						//fwrite(p_features, sizeof(float), 1, fout);
						//fwrite(",", sizeof(char), 1, fout);
						fprintf(fout, "%f", *p_features);
						fprintf(fout, "%s", ",");
					}
					calFeatures(backward_flow, features);
					for (p_features = features; p_features < features + 21; p_features++) {
						//fwrite(p_features, sizeof(float), 1, fout);
						//fwrite(",", sizeof(char), 1, fout);
						fprintf(fout, "%f", *p_features);
						fprintf(fout, "%s", ",");
					}
					fprintf(fout, "%s", "\n");

					printf("features saved\n");

					//delete expired flow
					flow_list = deleteFlow(flow_list, flow_id);
					printf("expired flow deteleted\n");
					//delete f and b flow
					FLOW* f_1, * f_2;
					f_1 = forward_flow;
					while (f_1 != NULL) {
						f_2 = f_1->next;
						free(f_1);
						f_1 = NULL;
						f_1 = f_2;
					}
					f_1 = backward_flow;
					while (f_1 != NULL) {
						f_2 = f_1->next;
						free(f_1);
						f_1 = NULL;
						f_1 = f_2;
					}


					//create new flow // add
					flow = createFlow(pkt);
					flow_list = addFlow(flow_list, flow, flow_id);
					printf("new flow created\n");
				}
			}
		}
		else {// not in flow
			printf("packet %d is not in flow\n", pkt_num);
			//create new flow
			flow = createFlow(pkt);
			//add new flow to flow list
			printf("add new flow to flow list\n");
			flow_list = addFlow(flow_list, flow, flow_id);
		}
	}

	//read end of file, loop to calculate  features of reamaining flow, calculate one and then delete one
	printf("calculate final features\n");
	FlowList* p1, * p2;
	p1 = flow_list;
	while (p1 != NULL) {
		//if only one pkt
		if (p1->flow->next == NULL) {
			flow_list = p1->next;
			free(p1->flow->pkt);
			free(p1->flow);
			p1 = flow_list;
		}
		else //cal features and delete
		{

			FLOW* temp_h1, * temp_h2;
			temp_h1 = p1->flow;
			int forward_num = 0;
			int backward_num = 0;

			FLOW* forward_flow;
			forward_flow = NULL;
			FLOW* backward_flow;
			backward_flow = NULL;

			while (temp_h1 != NULL) {// split into forward and backward flow


				FLOWID id = genFlowId(temp_h1->pkt);
				if (0 == strcmp(id.forward_id, p1->flow_id.forward_id)) { //forward
					forward_num++;
					if (1 == forward_num) { //create forward flow list
						forward_flow = createFlow(temp_h1->pkt);
						//forward_list = createFlowList(forward_flow, &flow_id);
					}
					else {// add pkt to forward flow list
						addPacket(forward_flow, temp_h1->pkt);
					}
				}
				if (0 == strcmp(id.forward_id, p1->flow_id.backward_id)) {// backward
					backward_num++;
					if (1 == backward_num) {
						backward_flow = createFlow(temp_h1->pkt);
					}
					else
					{
						addPacket(backward_flow, temp_h1->pkt);
					}
				}
				temp_h2 = temp_h1->next;
				temp_h1 = temp_h2;
			}



			calFeatures(p1->flow, features);

			sprintf(sip, "%d.%d.%d.%d", (p1->flow->pkt->src_ip >> 24) & 0x000000ff,
				(p1->flow->pkt->src_ip) >> 16 & 0x000000ff, (p1->flow->pkt->src_ip >> 8) & 0x000000ff,
				p1->flow->pkt->src_ip & 0x000000ff);
			fprintf(fout, "%s", sip);
			fprintf(fout, "%s", ",");
			fprintf(fout, "%d", p1->flow->pkt->src_port);
			fprintf(fout, "%s", ",");
			sprintf(dip, "%d.%d.%d.%d", (p1->flow->pkt->dst_ip >> 24) & 0x000000ff,
				(p1->flow->pkt->dst_ip) >> 16 & 0x000000ff, (p1->flow->pkt->dst_ip >> 8) & 0x000000ff,
				p1->flow->pkt->dst_ip & 0x000000ff);
			fprintf(fout, "%s", dip);
			fprintf(fout, "%s", ",");
			fprintf(fout, "%d", p1->flow->pkt->dst_port);
			fprintf(fout, "%s", ",");
			fprintf(fout, "%d", p1->flow->pkt->protocol);
			fprintf(fout, "%s", ",");

			//save features
			for (p_features = features; p_features < features + 21; p_features++) {
				//fwrite(p_features, sizeof(float), 1, fout);
				//fwrite(",", sizeof(char), 1, fout);
				fprintf(fout, "%f", *p_features);
				fprintf(fout, "%s", ",");
			}
			calFeatures(forward_flow, features);
			for (p_features = features; p_features < features + 21; p_features++) {
				//fwrite(p_features, sizeof(float), 1, fout);
				//fwrite(",", sizeof(char), 1, fout);
				fprintf(fout, "%f", *p_features);
				fprintf(fout, "%s", ",");
			}
			calFeatures(backward_flow, features);
			for (p_features = features; p_features < features + 21; p_features++) {
				//fwrite(p_features, sizeof(float), 1, fout);
				//fwrite(",", sizeof(char), 1, fout);
				fprintf(fout, "%f", *p_features);
				fprintf(fout, "%s", ",");
			}
			fprintf(fout, "%s", "\n");
			flow_list = p1->next;
			// delete current flow
			free(p1->flow->pkt);
			free(p1->flow);
			p1 = flow_list;

			//delete f and b flow
			FLOW* f_1, * f_2;
			f_1 = forward_flow;
			while (f_1 != NULL) {
				f_2 = f_1->next;
				free(f_1);
				f_1 = NULL;
				f_1 = f_2;
			}
			f_1 = backward_flow;
			while (f_1 != NULL) {
				f_2 = f_1->next;
				free(f_1);
				f_1 = NULL;
				f_1 = f_2;
			}
		}
	}

	fclose(fout);
	fclose(fp);

	free(features);

	//free(file_header_t);
	free(pkt_header_t);
	pkt_header_t = NULL;
	free(frame_header_t);
	frame_header_t = NULL;
	free(ip_header_t);
	ip_header_t = NULL;
	free(tcp_header_t);
	tcp_header_t = NULL;
	free(udp_header_t);
	udp_header_t = NULL;

	free(pkt_offset);
	pkt_offset = NULL;

	//iterate to free mem
	FlowList* p, * temp;
	FLOW* flow_temp;
	p = flow_list;
	while (p != NULL) {
		temp = p->next;
		//
		while (p->flow != NULL) {
			flow_temp = p->flow->next;
			free(p->flow->pkt);
			p->flow->pkt = NULL;
			free(p->flow);
			p->flow = NULL;
			p->flow = flow_temp;
		}
		free(p);
		p = NULL;
		p = temp;
	}
}
