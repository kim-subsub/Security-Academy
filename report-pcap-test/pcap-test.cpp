#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define IP_PROTO_TCP 6

#pragma pack(push, 1)
struct EthHdr {
	uint8_t dmac[6];
	uint8_t smac[6];
	uint16_t type;
};

struct IpHdr {
	uint8_t v_hl;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t sum;
	uint32_t sip;
	uint32_t dip;
};

struct TcpHdr {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint8_t off_rsv;
	uint8_t flags;
	uint16_t win;
	uint16_t sum;
	uint16_t urp;
};
#pragma pack(pop)

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(const uint8_t* mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {
	struct in_addr addr;
	addr.s_addr = ip;
	printf("%s", inet_ntoa(addr));
}

void print_data(const uint8_t* data, uint32_t len) {
	uint32_t print_len = len;
	if (print_len > 20) print_len = 20;

	for (uint32_t i = 0; i < print_len; i++) {
		printf("%02x ", data[i]);
	}
}

void print_packet(const u_char* packet, uint32_t caplen) {
	if (caplen < sizeof(EthHdr)) return;

	EthHdr* eth = (EthHdr*)packet;
	if (ntohs(eth->type) != ETHERTYPE_IP) return;

	if (caplen < sizeof(EthHdr) + sizeof(IpHdr)) return;

	IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
	uint8_t ip_header_len = (ip->v_hl & 0x0f) * 4;
	if (ip->proto != IP_PROTO_TCP) return;
	if (ip_header_len < sizeof(IpHdr)) return;

	if (caplen < sizeof(EthHdr) + ip_header_len + sizeof(TcpHdr)) return;

	TcpHdr* tcp = (TcpHdr*)(packet + sizeof(EthHdr) + ip_header_len);
	uint8_t tcp_header_len = ((tcp->off_rsv >> 4) & 0x0f) * 4;
	if (tcp_header_len < sizeof(TcpHdr)) return;

	uint32_t header_len = sizeof(EthHdr) + ip_header_len + tcp_header_len;
	if (caplen < header_len) return;

	uint16_t ip_total_len = ntohs(ip->len);
	uint32_t data_len = 0;
	if (ip_total_len > ip_header_len + tcp_header_len) {
		data_len = ip_total_len - ip_header_len - tcp_header_len;
	}

	uint32_t captured_data_len = caplen - header_len;
	if (data_len > captured_data_len) {
		data_len = captured_data_len;
	}

	const uint8_t* data = packet + header_len;

	printf("ETH src mac: ");
	print_mac(eth->smac);
	printf("\n");

	printf("ETH dst mac: ");
	print_mac(eth->dmac);
	printf("\n");

	printf("IP src ip: ");
	print_ip(ip->sip);
	printf("\n");

	printf("IP dst ip: ");
	print_ip(ip->dip);
	printf("\n");

	printf("TCP src port: %u\n", ntohs(tcp->sport));
	printf("TCP dst port: %u\n", ntohs(tcp->dport));

	printf("Payload: ");
	print_data(data, data_len);
	printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		print_packet(packet, header->caplen);
	}

	pcap_close(pcap);
}
