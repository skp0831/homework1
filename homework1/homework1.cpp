#include <winsock2.h>

#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")

#pragma comment(lib,"wpcap.lib")

#define MAC_ADDR_LEN    6

		//	함수
typedef struct _ethernet_HEADER		//ethernet 헤더 구조체

{

	u_int8_t dest_mac[MAC_ADDR_LEN];	/* destination ethernet address */

	u_int8_t src_mac[MAC_ADDR_LEN];		/* source ethernet address */

	u_int16_t ethernet_protocol;		/* protocol */

}ethernet_HEADER, *Pethernet_HEADER;

typedef struct _IP_HEADER		//IP 헤더 구조체

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

typedef struct _TCP_HEADER		//TCP 헤더 구조체
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


		//	함수
void check_ethernet();		// 이더넷 체크
void ViewMac(unsigned char *mac);		//이더넷 맥 주소 체크
void check_IP();		//IP 체크
void check_TCP();		//TCP 체크
void check_data();		//data 체크
BOOL initpcap();		// initpcap() - 캡처 장치 초기화




		//	전역 변수

pcap_t				*adhandle;
struct pcap_pkthdr	*header;
const u_char		*pkt;
u_char				tcpdata;



int main()

{

	if (initpcap() == FALSE)	return 1;		//캡처 장치 초기화

	int res;
	int cnt = 0;

	while ((res = pcap_next_ex(adhandle, &header, &pkt)) >= 0)		//패킷 캡쳐

	{

	


		if (res == 0) continue;  // 패킷이 없을 경우 BACK
		printf("\n\n■■■■■■■■■■■■■■■■■■■■■■■■■■■■ Packet No : %d ■■■\n", cnt);

		cnt++;

		check_ethernet();  // ethernet 체크

		Pethernet_HEADER eh = (Pethernet_HEADER)((UCHAR *)pkt);		// 패킷에서 ethernet header 추출

		if (ntohs(eh->ethernet_protocol) != 0x800) continue;		// IP가 아닌경우 BACK


		check_IP();		// IP 체크

		PIP_HEADER ih = (PIP_HEADER)((UCHAR *)pkt + 14);		// 패킷에서 IP header 추출(pkt + ethernet size)

		if (ih->ip_protocol != 6) continue;		// TCP가 아닌경우 BACK

		check_TCP();		// TCP 체크

		check_data();		// DATA 체크
	}

	return 0;

}






BOOL initpcap()		//캡처 장치 찾기 및 초기화

{

	pcap_if_t *alldevs;		//장치 변수

	char errbuf[256];		//버퍼

	bpf_u_int32 NetMask;

	struct bpf_program fcode;

	pcap_if_t *d;




	// PCAP 초기화

	printf("!] PCAP을 초기화 중입니다... \n");



	if (pcap_findalldevs(&alldevs, errbuf) == -1)		//장치 목록 검사

	{

		printf("?] pcap_findalldevs 에서 문제 발생 \n");

		return FALSE;

	}



	for (d = alldevs; d->next != NULL; d = d->next);		// 장치를 찾을때 까지 검색



	printf("!] 네트워크 카드 명 [ %s ] \n", d->description);		// 네트워크 카드명 출력




	// 장치 열기

	if ((adhandle = pcap_open_live(d->name,	// 장치 명

		65536,									// 패킷당 버퍼 사이즈

		0,										// promiscuous mode

		0,										// read timeout

		errbuf									// 에러 버퍼

	)) == NULL)

	{

		printf("?] [ %s ] 는 winpcap에서 지원하지 않습니다.\n", d->name);

		pcap_freealldevs(alldevs);	// 장치 목록 해제

		return FALSE;

	}




	pcap_freealldevs(alldevs);




	NetMask = 0xffffff;




	// 필터명으로 컴파일

	if (pcap_compile(adhandle, &fcode, "tcp or udp", 1, NetMask) < 0)

	{

		printf("?] pcap_compile에서 문제 발생 \n");

		return FALSE;

	}




	// 필터 set

	if (pcap_setfilter(adhandle, &fcode)<0)

	{

		printf("?] pcap_setfilter에서 문제 발생 \n");

		return FALSE;

	}




	printf("!] PCAP 초기화 완료... \n");

	return TRUE;

}

void check_ethernet()		//ethernet 체크
{
	Pethernet_HEADER eh = (Pethernet_HEADER)((UCHAR *)pkt);		//패킷에서 ethernet header 추출

	printf("----------ethernet_Header----------------------------\n");
	printf(" DEST MAC : ");
	ViewMac(eh->dest_mac);		// mac 주소 출력

	printf("\n  SRC MAC : ");
	ViewMac(eh->src_mac);		// mac 주소 출력
	printf("\n     ");

	switch (ntohs(eh->ethernet_protocol))		// 프로토콜 분석 및 출력

	{

	case 0x800:	// ip 프로토콜 0x0800

		printf("Tpye : IP\n");

		break;


	default:

		printf("Tpye : Unknown[%d] \n", ntohs(eh->ethernet_protocol));

		break;

	}
};

void ViewMac(unsigned char *mac)	//MAC 주소 출력 함수

{

	int i;

	for (i = 0; i < MAC_ADDR_LEN; ++i)

	{

		printf("%02X-", mac[i]);

	}

}

void check_IP()		//IP 체크
{
	IN_ADDR addr;

	/*IN_ADDR 구조체
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


	IP_HEADER * ih = (IP_HEADER *)(pkt + 14);		// 패킷에서 IP header 추출(pkt + ethernet size)

	printf("-------------IP_Header-------------------------------\n");

	addr.s_addr = ih->dest_ip;		//IP header에서 dest_IP 추출 

	printf(" DEST IP : %s\n", inet_ntoa(addr));		// 32비트 값을 닷-십진법의 주소값으로 변환 후 출력

	addr.s_addr = ih->src_ip;		//IP header에서 src_IP 추출 

	printf("  SRC IP : %s", inet_ntoa(addr));		// 32비트 값을 닷-십진법의 주소값으로 변환 후 출력
	printf("\n    ");


	switch (ih->ip_protocol)		// 프로토콜 분석 및 출력

	{

	case 6:	// TCP 프로토콜 6

		printf("Tpye : TCP \n");

		break;


	default:

		printf("Tpye : Unkown[%d] \n", ih->ip_protocol);

		break;

	}
};

void check_TCP()		//TCP 체크
{

	TCP_HEADER * th = (TCP_HEADER *)(pkt + 14 + 20);		// 패킷에서 TCP header 추출(pkt + ethernet size(14) + IP size(20))

	printf("-------------TCP_Header------------------------------\n");

	printf(" DEST PORT : %d\n", ntohs(th->TCP_dest_port));		//16비트의 네트워크 바이트 오더를 호스트 바이트 오더로 변환후 출력(빅-인디언 -> 리틀-인디언)

	printf("  SRC PORT : %d", ntohs(th->TCP_src_port));



}

void check_data()		//DATA 체크
{
	printf("\n-------------TCP_Data--------------------------------\n data : ");

	if (*(pkt + 14 + 20 + 20) == 0)		// 패킷에서 DATA 부분(pkt + ethernet size(14) + IP size(20) + TCP size(20))이 비어있다면 null 출력 및 back
	{
		printf("Null");
		return;
	}



	int i = 0;

	while ((tcpdata = *(pkt + 14 + 20 + 20 + i)) != 0)		//DATA 부분 헥사값으로 출력	
	{
		i++;
		printf("%0X", tcpdata);
	}

}