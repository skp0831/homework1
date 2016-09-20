#include <winsock2.h>

#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")

#pragma comment(lib,"wpcap.lib")

#define MAC_ADDR_LEN    6

		//	�Լ�
typedef struct _ethernet_HEADER		//ethernet ��� ����ü

{

	u_int8_t dest_mac[MAC_ADDR_LEN];	/* destination ethernet address */

	u_int8_t src_mac[MAC_ADDR_LEN];		/* source ethernet address */

	u_int16_t ethernet_protocol;		/* protocol */

}ethernet_HEADER, *Pethernet_HEADER;

typedef struct _IP_HEADER		//IP ��� ����ü

{
	u_int8_t	ip_headerlengthversion;      /* header length + version */

	u_int8_t	ip_typeofservice;       /* type of service */

	u_int16_t	ip_totallenng;         /* total length */
	u_int16_t	ip_identification;          /* identification */
	u_int16_t	ip_flags;	// Flags (3 bits) + Fragment offset (13 bits)
#define DONT_FRAG(frag)   (frag & 0x40)

#define MORE_FRAG(frag)   (frag & 0x20)

#define FRAG_OFFSET(frag) (ntohs(frag) & (~0x6000))

	u_int8_t ip_timetolive;          /* time to live */
	u_int8_t ip_protocol;            /* protocol */
	u_int16_t ip_checksumsum;         /* checksum */

	UINT	src_ip;			// Source address
	UINT	dest_ip;			// Destination address

	UINT		op_pad;			// Option + Padding

}IP_HEADER, *PIP_HEADER;

typedef struct _TCP_HEADER		//TCP ��� ����ü
{
	u_int16_t TCP_src_port;       /* source port */
	u_int16_t TCP_dest_port;       /* destination port */
	u_int32_t TCP_sequence;          /* sequence number */
	u_int32_t TCP_ack;          /* acknowledgement number */
	u_int8_t  th_flags;       /* control flags */

#define TH_FIN    0x01      /* finished send data */

#define TH_SYN    0x02      /* synchronize sequence numbers */

#define TH_RST    0x04      /* reset the connection */

#define TH_PUSH   0x08      /* push data to the app layer */

#define TH_ACK    0x10      /* acknowledge */

#define TH_URG    0x20      /* urgent! */

#define TH_ECE    0x40

#define TH_CWR    0x80

	u_int16_t TCP_win;         /* window */
	u_int16_t TCP_sum;         /* checksum */
	u_int16_t TCP_urp;         /* urgent pointer */

}TCP_HEADER, *PTCP_HEADER;


		//	�Լ�
void check_ethernet();		// �̴��� üũ
void ViewMac(unsigned char *mac);		//�̴��� �� �ּ� üũ
void check_IP();		//IP üũ
void check_TCP();		//TCP üũ
void check_data();		//data üũ
BOOL initpcap();		// initpcap() - ĸó ��ġ �ʱ�ȭ




		//	���� ����

pcap_t				*adhandle;
struct pcap_pkthdr	*header;
const u_char		*pkt;
u_char				tcpdata;



int main()

{

	if (initpcap() == FALSE)	return 1;		//ĸó ��ġ �ʱ�ȭ

	int res;
	int cnt = 0;

	while ((res = pcap_next_ex(adhandle, &header, &pkt)) >= 0)		//��Ŷ ĸ��

	{

	


		if (res == 0) continue;  // ��Ŷ�� ���� ��� BACK
		printf("\n\n����������������������������� Packet No : %d ����\n", cnt);

		cnt++;

		check_ethernet();  // ethernet üũ

		Pethernet_HEADER eh = (Pethernet_HEADER)((UCHAR *)pkt);		// ��Ŷ���� ethernet header ����

		if (ntohs(eh->ethernet_protocol) != 0x800) continue;		// IP�� �ƴѰ�� BACK


		check_IP();		// IP üũ

		PIP_HEADER ih = (PIP_HEADER)((UCHAR *)pkt + 14);		// ��Ŷ���� IP header ����(pkt + ethernet size)

		if (ih->ip_protocol != 6) continue;		// TCP�� �ƴѰ�� BACK

		check_TCP();		// TCP üũ

		check_data();		// DATA üũ
	}

	return 0;

}






BOOL initpcap()		//ĸó ��ġ ã�� �� �ʱ�ȭ

{

	pcap_if_t *alldevs;		//��ġ ����

	char errbuf[256];		//����

	bpf_u_int32 NetMask;

	struct bpf_program fcode;

	pcap_if_t *d;




	// PCAP �ʱ�ȭ

	printf("!] PCAP�� �ʱ�ȭ ���Դϴ�... \n");



	if (pcap_findalldevs(&alldevs, errbuf) == -1)		//��ġ ��� �˻�

	{

		printf("?] pcap_findalldevs ���� ���� �߻� \n");

		return FALSE;

	}



	for (d = alldevs; d->next != NULL; d = d->next);		// ��ġ�� ã���� ���� �˻�



	printf("!] ��Ʈ��ũ ī�� �� [ %s ] \n", d->description);		// ��Ʈ��ũ ī��� ���




	// ��ġ ����

	if ((adhandle = pcap_open_live(d->name,	// ��ġ ��

		65536,									// ��Ŷ�� ���� ������

		0,										// promiscuous mode

		0,										// read timeout

		errbuf									// ���� ����

	)) == NULL)

	{

		printf("?] [ %s ] �� winpcap���� �������� �ʽ��ϴ�.\n", d->name);

		pcap_freealldevs(alldevs);	// ��ġ ��� ����

		return FALSE;

	}




	pcap_freealldevs(alldevs);




	NetMask = 0xffffff;




	// ���͸����� ������

	if (pcap_compile(adhandle, &fcode, "tcp or udp", 1, NetMask) < 0)

	{

		printf("?] pcap_compile���� ���� �߻� \n");

		return FALSE;

	}




	// ���� set

	if (pcap_setfilter(adhandle, &fcode)<0)

	{

		printf("?] pcap_setfilter���� ���� �߻� \n");

		return FALSE;

	}




	printf("!] PCAP �ʱ�ȭ �Ϸ�... \n");

	return TRUE;

}

void check_ethernet()		//ethernet üũ
{
	Pethernet_HEADER eh = (Pethernet_HEADER)((UCHAR *)pkt);		//��Ŷ���� ethernet header ����

	printf("----------ethernet_Header----------------------------\n");
	printf(" DEST MAC : ");
	ViewMac(eh->dest_mac);		// mac �ּ� ���

	printf("\n  SRC MAC : ");
	ViewMac(eh->src_mac);		// mac �ּ� ���
	printf("\n     ");

	switch (ntohs(eh->ethernet_protocol))		// �������� �м� �� ���

	{

	case 0x800:	// ip �������� 0x0800

		printf("Tpye : IP\n");

		break;


	default:

		printf("Tpye : Unknown[%d] \n", ntohs(eh->ethernet_protocol));

		break;

	}
};

void ViewMac(unsigned char *mac)	//MAC �ּ� ��� �Լ�

{

	int i;

	for (i = 0; i < MAC_ADDR_LEN; ++i)

	{

		printf("%02X-", mac[i]);

	}

}

void check_IP()		//IP üũ
{
	IN_ADDR addr;

	/*IN_ADDR ����ü
	struct in_addr{
		union {
			struct {
				unsigned char s_b1,
							  s_b2,
							  s_b3,
							  s_b4;
			} S_un_b;
			struct {
				unsigned short s_w1,
							   s_w2;
			} S_um_w;
			unsigned long S_addr;
		} S_un;
	};										*/


	IP_HEADER * ih = (IP_HEADER *)(pkt + 14);		// ��Ŷ���� IP header ����(pkt + ethernet size)

	printf("-------------IP_Header-------------------------------\n");

	addr.s_addr = ih->dest_ip;		//IP header���� dest_IP ���� 

	printf(" DEST IP : %s\n", inet_ntoa(addr));		// 32��Ʈ ���� ��-�������� �ּҰ����� ��ȯ �� ���

	addr.s_addr = ih->src_ip;		//IP header���� src_IP ���� 

	printf("  SRC IP : %s", inet_ntoa(addr));		// 32��Ʈ ���� ��-�������� �ּҰ����� ��ȯ �� ���
	printf("\n    ");


	switch (ih->ip_protocol)		// �������� �м� �� ���

	{

	case 6:	// TCP �������� 6

		printf("Tpye : TCP \n");

		break;


	default:

		printf("Tpye : Unkown[%d] \n", ih->ip_protocol);

		break;

	}
};

void check_TCP()		//TCP üũ
{

	TCP_HEADER * th = (TCP_HEADER *)(pkt + 14 + 20);		// ��Ŷ���� TCP header ����(pkt + ethernet size(14) + IP size(20))

	printf("-------------TCP_Header------------------------------\n");

	printf(" DEST PORT : %d\n", ntohs(th->TCP_dest_port));		//16��Ʈ�� ��Ʈ��ũ ����Ʈ ������ ȣ��Ʈ ����Ʈ ������ ��ȯ�� ���(��-�ε�� -> ��Ʋ-�ε��)

	printf("  SRC PORT : %d", ntohs(th->TCP_src_port));



}

void check_data()		//DATA üũ
{
	printf("\n-------------TCP_Data--------------------------------\n data : ");

	if (*(pkt + 14 + 20 + 20) == 0)		// ��Ŷ���� DATA �κ�(pkt + ethernet size(14) + IP size(20) + TCP size(20))�� ����ִٸ� null ��� �� back
	{
		printf("Null");
		return;
	}



	int i = 0;

	while ((tcpdata = *(pkt + 14 + 20 + 20 + i)) != 0)		//DATA �κ� ��簪���� ���	
	{
		i++;
		printf("%0X", tcpdata);
	}

}