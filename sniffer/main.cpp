#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<cassert>

#include <linux/route.h>
#include<netinet/ip_icmp.h>
#include<netinet/igmp.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<netinet/ip6.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

#include <netpacket/packet.h>


#include<string>

using namespace std;

void ProcessIPPacket(unsigned char*, int);
void ProcessIP6Packet(unsigned char*, int);
void PrintData (unsigned char*, int);
void print_ip_header(unsigned char*, int);
void print_ip6_header(unsigned char*, int);
void print_arp_header(unsigned char*, int);
void print_ethernet_header(unsigned char*, int);
void print_tcp_packet(unsigned char *, int );
void print_udp_packet(unsigned char *, int );
void print_icmp_packet(unsigned char*, int );
void print_igmp_packet(unsigned char*, int );
void lookup_arp(struct in_addr& ipaddr, int send_fd);

FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,ip6=0,arp=0,total=0,i,j;

bool noeth     = false;
bool forcewait = false;
static struct sockaddr_ll fromAddr;
static struct sockaddr_ll servAddr;
static string iface_name = "lo";
static struct in_addr iface_ip;


namespace {
    inline u_int32_t replaceIpAndReturnChecksumDiff(u_int32_t* replace_ip, u_int32_t new_ip)
    {
        u_int32_t diff = (*replace_ip - new_ip);
        if( *replace_ip < new_ip )
            diff--;
        *replace_ip = new_ip;
        return diff;
    }


    u_int16_t checksumBySklarov(u_int16_t* addr, u_int32_t len)
    {
        u_int16_t result;
        u_int32_t sum=0;

        while(len > 1)
        {
            if( len != 10 ) /* skip checksum field */
                sum += *addr;
            len -= 2;
            addr++;
        }

        if( len == 1 )
            sum += *(unsigned char*)addr;
        uint16_t* ptrSum = (uint16_t*)&sum;
        sum = *ptrSum + *(ptrSum+1);
        sum += (sum > 0xffff) ? 1 : 0;
        result = ~sum;

        return result;
    }
}

int main(int argc, char* argv[])
{
    printf("\n"
           "Usage: ./sniffer <name> opt:[noeth] opt:[wait]\n"
           "name   Name of listening interface (\"lo\" default)\n"
           "noeth  IP only in case if no eth headers (PPP, ISDN, etc)\n"
           "wait   If interface unavailable but should be diagnosed immediately after start\n\n");

    if( argc > 1)
        iface_name = argv[1];

    for(unsigned char i = 2; i < 4; i++ ) {
        if( argc > i ) {
            if( !noeth && (0 == strcmp(argv[i],"noeth") || 0 == strcmp(argv[i],"nohdr")) )
                noeth = true;
            else if( !forcewait && (0 == strcmp(argv[i],"wait")) )
                forcewait = true;
        }
    }


    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    if(sock_raw < 0)
    {
        perror("::socket Error");
        return 1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface_name.c_str() );
    if( ::ioctl(sock_raw, SIOCGIFADDR, &ifr) < 0 )
        perror( "::ioctl Cannot obtain IP address of device!" );
    else
        memcpy(&(iface_ip.s_addr), &(ifr.ifr_ifru.ifru_addr.sa_data[2]), 4);

    memset(&servAddr, 0, sizeof(struct sockaddr_ll));

    bool errprompt = false;
    while( ::ioctl( sock_raw, SIOCGIFINDEX, &ifr) < 0 ) {
        if( !errprompt ) {
            perror("::ioctl SIOCGIFINDEX error: ");
            if( !forcewait )
                return 1;
            errprompt = true;
        }
        continue;
    }

    if( errprompt ) {
        printf("\nRestored!\n");
        errprompt = false;
    }

    printf("Establishing...\n");
    servAddr.sll_ifindex = ifr.ifr_ifindex;

    while( ::ioctl(sock_raw, SIOCGIFHWADDR, &ifr) < 0 )
    {
        if( !errprompt ) {
            perror( "::ioctl Cannot obtain HW address of device: " );
            if( !forcewait )
                return 1;
            errprompt = true;
        }
        continue;
    }
    if( errprompt ) {
        printf("\nRestored!\n");
        errprompt = false;
    }

    for (int i = 0; i < ETH_ALEN; i++)
        servAddr.sll_addr[i] = ifr.ifr_hwaddr.sa_data[i];

    servAddr.sll_family   = PF_PACKET;
    servAddr.sll_protocol = htons(ETH_P_ALL);
    servAddr.sll_halen    = ETH_ALEN;
    servAddr.sll_hatype   = 1; /* Ethernet 10Mbps */
    servAddr.sll_pkttype  = PACKET_BROADCAST;

    while( ::bind(sock_raw, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0 )
    {
        if( !errprompt ) {
            perror("::bind error: ");
            if( !forcewait )
                return 1;
            errprompt = true;
        }
        continue;
    }
    if( errprompt ) {
        printf("\nRestored!\n");
        errprompt = false;
    }

    unsigned char* tmp = (unsigned char*)&(servAddr.sll_addr[0]);
    printf("Stared on \"%s\" (%d) %02x:%02x:%02x:%02x:%02x:%02x, IP %s\n",
           iface_name.c_str(), servAddr.sll_ifindex, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5],
           inet_ntoa(iface_ip) );

    unsigned char *buffer = (unsigned char *) malloc(65536);
/*
    in_addr tmpaddr;
    inet_aton("217.1.1.1",&tmpaddr);


    FILE* ttt = fopen("google.icmp", "rb");
    char ibuf[256];
    int bnum = fread(ibuf,1,255,ttt);
    fclose(ttt);

    u_int8_t newmac[ETH_ALEN];
    newmac[0] = 0x08;
    newmac[1] = 0x00;
    newmac[2] = 0xfb;
    newmac[3] = 0x01;
    newmac[4] = 0x02;
    newmac[5] = 0xa1;

    struct ethhdr* ieth = (struct ethhdr*)(ibuf);
    memcpy(ieth->h_source,newmac,ETH_ALEN);

    int bsent = sendto(sock_raw, buffer, bnum, 0, (struct sockaddr*)&servAddr, sizeof(servAddr));
    if( bsent <= 0 ) {
        perror("Experiment failed");
        return -1;
    }
*/
    while(1)
    {
        //Receive a packet
        socklen_t addrSize = sizeof fromAddr;
        memcpy(&fromAddr, &servAddr, addrSize);
        //memset(&fromAddr, 0, addrSize);

        int data_size = recvfrom(sock_raw, buffer, 65536, 0, (sockaddr*)&fromAddr, &addrSize);
        if( data_size < 0 )
        {
            if( !errprompt ) {
                perror("Error interface listening: ");
                if( !forcewait )
                    return 1;
                errprompt = true;
            }
            continue;
        }
        if( errprompt ) {
            printf("\nRestored!\n");
            errprompt = false;
        }

        if(data_size < ETH_ALEN) {
            printf("\nWarning: Received data size is %d\n", data_size);
            for(unsigned char i = 0; i < data_size; ++i)
                printf("%.2x ", buffer[i]);
            printf("\n\n");
            continue;
        }

        struct ethhdr* pEth = (struct ethhdr*)buffer;
        if( (pEth->h_proto == htons(ETH_P_IP)) || noeth )
        {
            ProcessIPPacket(buffer, data_size);
        }
        else if( pEth->h_proto == htons(ETH_P_IPV6) )
        {
            logfile=fopen("ipv6.txt","a+");
            if(logfile==NULL)
                printf("Unable to create ipv6.txt file.");
            print_ip6_header(buffer, data_size);
        }
        else if( pEth->h_proto == htons(ETH_P_ARP) )
        {
            logfile=fopen("arp.txt","a+");
            if(logfile==NULL)
                printf("Unable to create arp.txt file.");
            print_arp_header(buffer, data_size);
        }
        else {
            logfile=fopen("undiscovered.txt","a+");
            if(logfile==NULL)
                printf("Unable to create undiscovered.txt file.");
            print_ethernet_header( (unsigned char*)pEth, data_size);
            ++others;
        }
        fclose(logfile);

        printf("TCP:%d UDP:%d ICMP:%d IGMP:%d IP6:%d ARP:%d Other:%d Total:%d\r",
               tcp, udp, icmp, igmp, ip6, arp, others, total);
    }

    close(sock_raw);
    printf("Finished");
    return 0;
}

void ProcessIPPacket(unsigned char* buffer, int size)
{
    unsigned short ethlen = noeth ? 0 : sizeof(struct ethhdr);
    struct ip *iph = (struct ip*)(buffer + ethlen);

/*    in_addr tmpaddr;
    inet_aton("217.1.1.1",&tmpaddr);

    struct icmp* icmph=(struct icmp*)(buffer+20);
    if( (iph->ip_p == 1) &&
        (iph->ip_dst.s_addr == tmpaddr.s_addr) &&
        (icmph->icmp_type == ICMP_ECHO))
    {
        FILE* ttt = fopen("google.icmp", "wb");
        fwrite(buffer,1,size,ttt);
        fclose(ttt);
    }

    {
        FILE* ttt = fopen("yandextest.tcp", "wb");
        fwrite(buffer,1,size,ttt);
        fclose(ttt);
    }
    */

    switch (iph->ip_p) //Check the Protocol and do accordingly...
    {
        case 1:
            logfile=fopen("icmp.txt","a+");
            if(logfile==NULL)
                printf("Unable to create icmp.txt file.");
            print_icmp_packet(buffer, size);
            break;
        case 2:
            logfile=fopen("igmp.txt","a+");
            if(logfile==NULL)
                printf("Unable to create igmp.txt file.");
            print_igmp_packet(buffer, size);
            break;
        case 6:
            logfile=fopen("tcp.txt","a+");
            if(logfile==NULL)
                printf("Unable to create tcp.txt file.");
                    print_tcp_packet(buffer, size);
            break;
        case 17:
            logfile=fopen("udp.txt","a+");
            if(logfile==NULL)
                printf("Unable to create udp.txt file.");
            print_udp_packet(buffer, size);
            break;
        default:
            fclose(logfile);
            logfile=fopen("undiscovered.txt","a+");
            if(logfile==NULL)
                printf("Unable to create undiscovered.txt file.");

            print_ip_header(buffer, size);
            ++others;
            break;
    }
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    fprintf(logfile , "\n###########################################################\n");
    fprintf(logfile , "Frame Size: %d bytes\n", Size);
    switch( fromAddr.sll_pkttype )
    {
    case PACKET_HOST:
        fprintf(logfile , "Frame Type : INCOMING TO HOST\n");
    break;
    case PACKET_BROADCAST:
        fprintf(logfile , "Frame Type : BROADCAST\n");
    break;
    case PACKET_MULTICAST:
        fprintf(logfile , "Frame Type : MULTICAST TO GROUP\n");
    break;
    case PACKET_OTHERHOST:
        fprintf(logfile , "Frame Type : OTHERHOST\n");
    break;
    case PACKET_OUTGOING:
        fprintf(logfile , "Frame Type : OUTGOING FROM HOST\n");
    break;
    case PACKET_LOOPBACK:
        fprintf(logfile , "Frame Type : LOOPBACK\n");
    break;
    case PACKET_FASTROUTE:
        fprintf(logfile , "Frame Type : FASTROUTE\n");
    break;
    default:
        fprintf(logfile , "Frame Type : UNHANDLED (%d)\n", fromAddr.sll_pkttype);
        break;
    }

    if( noeth )
    {
        unsigned char* p = &(fromAddr.sll_addr[0]);
        fprintf(logfile , "Tunnel     : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n"
                          "Protocol   : 0x%.4x\n\n",
                          p[0], p[1], p[2], p[3], p[4], p[5], htons(fromAddr.sll_protocol) );
        return;
    }

    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "\nEthernet Header\n");
    fprintf(logfile , "   |-Dest Addr : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Src Addr  : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol  : 0x%.4X\n", ntohs(eth->h_proto) );
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    total++;

    print_ethernet_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ip *iph = (struct ip *)Buffer;

    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-Header   : %d bytes\n",((unsigned int)(iph->ip_hl))*4);
    fprintf(logfile , "   |-Version  : %d\n",(unsigned int)iph->ip_v);
    fprintf(logfile , "   |-Service  : %d\n",(unsigned int)iph->ip_tos);
    fprintf(logfile , "   |-Total    : %d bytes\n",ntohs(iph->ip_len));
    fprintf(logfile , "   |-Identfr  : %d\n",ntohs(iph->ip_id));
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ip_ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->ip_p);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->ip_sum));
    fprintf(logfile , "   |-Src  IP  : %s\n",inet_ntoa(iph->ip_src));
    fprintf(logfile , "   |-Dest IP  : %s\n",inet_ntoa(iph->ip_dst));

/*    u_int32_t oldIp = iph->ip_src.s_addr;
    u_int32_t newIp = 0xeeeeeeee;

    u_int16_t littleEndSum = ntohs(iph->ip_sum);

    u_int32_t sumOldCheck = checksumBySklarov((u_int16_t*)Buffer, (iph->ip_hl)*4);
    assert( sumOldCheck == iph->ip_sum );

    u_int32_t diff = replaceIpAndReturnChecksumDiff(&(iph->ip_src.s_addr), newIp);
    u_int32_t sumNew = (sumOldCheck+diff) % 0xffff;

    u_int32_t sumNewCheck = checksumBySklarov((u_int16_t*)Buffer, (iph->ip_hl)*4);
    assert( sumNew == sumNewCheck );
    */
}

void print_ip6_header(unsigned char* Buffer, int Size)
{
    total++;
    ip6++;

    print_ethernet_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ip6_hdr *iph = (struct ip6_hdr *)Buffer;

    fprintf(logfile , "IPv6 Header\n");
    fprintf(logfile , "   |-Header      : %d bytes\n",(int)sizeof(*iph));

    uint32_t flow32   = iph->ip6_ctlun.ip6_un1.ip6_un1_flow;
    uint8_t  ver      = (flow32 & 0x000000F0) >> 4;
    uint8_t  priority = (flow32 & 0x0000000F);
    uint32_t flowID   = ntohl( flow32 );
    flowID           &= 0x00FFFFFF;

    fprintf(logfile , "   |-IP Version  : %d\n",ver);
    fprintf(logfile , "   |-Priority    : %d\n",priority);
    fprintf(logfile , "   |-Flow ID     : %d\n",flowID);
    fprintf(logfile , "   |-Payload     : %d bytes\n",ntohs(iph->ip6_ctlun.ip6_un1.ip6_un1_plen));
    fprintf(logfile , "   |-Hop Limit   : %d\n",(unsigned int)iph->ip6_ctlun.ip6_un1.ip6_un1_hlim);

    uint8_t proto = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    switch( proto )
    {
    case IPPROTO_IPV6:
        fprintf(logfile , "   |-NextHdrType : IPv6 header\n");
        break;
    case IPPROTO_ROUTING:
        fprintf(logfile , "   |-NextHdrType : IPv6 routing header\n");
        break;
    case IPPROTO_FRAGMENT:
        fprintf(logfile , "   |-NextHdrType : IPv6 fragmentation header\n");
        break;
    case IPPROTO_ICMPV6:
        fprintf(logfile , "   |-NextHdrType : ICMPv6\n");
        break;
    case IPPROTO_DSTOPTS:
        fprintf(logfile , "   |-NextHdrType : IPv6 destination options\n");
        break;
    case IPPROTO_HOPOPTS:
        fprintf(logfile , "   |-NextHdrType : IPv6 Hop-by-Hop options\n");
        break;
    case IPPROTO_NONE:
        fprintf(logfile , "   |-NextHdrType : Data payload\n");
        break;
    case IPPROTO_UDP:
        fprintf(logfile , "   |-NextHdrType : UDP\n");
        break;
    case IPPROTO_TCP:
        fprintf(logfile , "   |-NextHdrType : TCP\n");
        break;
    default:
        fprintf(logfile , "   |-NextHdrType : %d (see RFC)\n", proto);
        break;
    }

    char tmpbuf[INET6_ADDRSTRLEN];
    fprintf(logfile , "   |-Src IP6     : %s\n",inet_ntop(AF_INET6,&(iph->ip6_src),tmpbuf,INET6_ADDRSTRLEN));
    fprintf(logfile , "   |-Dest IP6    : %s\n",inet_ntop(AF_INET6,&(iph->ip6_dst),tmpbuf,INET6_ADDRSTRLEN));

    fprintf(logfile , "\nData Payload %d bytes\n", Size-(int)sizeof(*iph));
    PrintData(Buffer + sizeof(*iph) , Size-sizeof(*iph) );
}

void print_arp_header(unsigned char* Buffer, int Size)
{
    total++;
    arp++;

    print_ethernet_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ether_arp *arh = (struct ether_arp *)Buffer;

    fprintf(logfile , "ARP Header\n");
    fprintf(logfile , "   |-Header        : %d bytes\n", (int)sizeof(*arh));
    fprintf(logfile , "   |-Fixed ARP Header\n");
    fprintf(logfile , "       |-HW Addr Fmt   : 0x%.4x\n", ntohs(arh->ea_hdr.ar_hrd) );
    fprintf(logfile , "       |-ProtoAddr Fmt : 0x%.4x\n", ntohs(arh->ea_hdr.ar_pro) );
    fprintf(logfile , "       |-HW Addr Len   : %d\n", arh->ea_hdr.ar_hln );
    fprintf(logfile , "       |-ProtoAddr Len : %d\n", arh->ea_hdr.ar_pln );

    uint16_t opt = ntohs(arh->ea_hdr.ar_op);
    if( opt == ARPOP_REQUEST )
        fprintf(logfile , "       |-ARP Command   : ARPOP_REQUEST 1\n");
    else if( opt == ARPOP_REPLY )
        fprintf(logfile , "       |-ARP Command   : ARPOP_REPLY 2\n");
    else if( opt == ARPOP_RREQUEST )
        fprintf(logfile , "       |-ARP Command   : ARPOP_RREQUEST 3\n");
    else if( opt == ARPOP_RREPLY )
        fprintf(logfile , "       |-ARP Command   : ARPOP_RREPLY 4\n");
    else if( opt == ARPOP_InREQUEST )
        fprintf(logfile , "       |-ARP Command   : ARPOP_InREQUEST 8\n");
    else if( opt == ARPOP_InREPLY )
        fprintf(logfile , "       |-ARP Command   : ARPOP_InREPLY 9\n");
    else if( opt == ARPOP_NAK )
        fprintf(logfile , "       |-ARP Command   : ARPOP_NAK 10\n");
    else
        fprintf(logfile , "       |-ARP Command   : %d (see RFC)\n", opt );

    fprintf(logfile , "   |-Snd HW Addr   : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", arh->arp_sha[0], arh->arp_sha[1], arh->arp_sha[2], arh->arp_sha[3], arh->arp_sha[4], arh->arp_sha[5]);
    fprintf(logfile , "   |-Tgt HW Addr   : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", arh->arp_tha[0], arh->arp_tha[1], arh->arp_tha[2], arh->arp_tha[3], arh->arp_tha[4], arh->arp_tha[5]);
    fprintf(logfile , "   |-Snd ProtoAddr : %d.%d.%d.%d\n", arh->arp_spa[0], arh->arp_spa[1], arh->arp_spa[2], arh->arp_spa[3]);
    fprintf(logfile , "   |-Tgr ProtoAddr : %d.%d.%d.%d\n", arh->arp_tpa[0], arh->arp_tpa[1], arh->arp_tpa[2], arh->arp_tpa[3]);

    fprintf(logfile , "\nData Payload %d bytes\n", Size-(int)sizeof(struct ether_arp));
    PrintData(Buffer + sizeof(*arh) , Size-sizeof(struct ether_arp) );
}

struct tcp_header
  {
    u_int16_t th_sport; /* source port */
    u_int16_t th_dport; /* destination port */
    u_int32_t th_seq;   /* sequence number */
    u_int32_t th_ack;   /* acknowledgement number */
    u_int8_t th_off;    /* data offset */
    u_int8_t th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
};

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    tcp++;

    print_ip_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ip *iph = (struct ip *)Buffer;
    int iphdrlen = iph->ip_hl*4;

    struct tcp_header *tcph=(struct tcp_header*)(Buffer+iphdrlen);
    int tcphdrlen = iphdrlen + ((tcph->th_off & 0xF0) >> 2);

    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-Header   : %d bytes\n", (tcph->th_off & 0xF0)>>2);
    fprintf(logfile, "   |-SrcPort  : %u\n", ntohs(tcph->th_sport));
    fprintf(logfile, "   |-DestPort : %u\n", ntohs(tcph->th_dport));
    fprintf(logfile, "   |-Sequence : %u\n", ntohl(tcph->th_seq));
    fprintf(logfile, "   |-Ack Num  : %u\n", ntohl(tcph->th_ack));
    fprintf(logfile, "   |-Flags    : 0x%x\n", tcph->th_flags);

    u_int8_t fl = tcph->th_flags & 0x3F; /* select 6 lower bits */
    if( (fl & TH_FIN) == TH_FIN )
        fprintf(logfile, "       |-Finish 0x01\n");
    if( (fl & TH_SYN) == TH_SYN )
        fprintf(logfile, "       |-Sync 0x02\n");
    if( (fl & TH_RST) == TH_RST )
        fprintf(logfile, "       |-Reset 0x04\n");
    if( (fl & TH_PUSH) == TH_PUSH )
        fprintf(logfile, "       |-Push 0x08\n");
    if( (fl & TH_ACK) == TH_ACK )
        fprintf(logfile, "       |-Ack 0x10\n");
    if( (fl & TH_URG) == TH_URG )
        fprintf(logfile, "       |-Urgent 0x20\n");

    fprintf(logfile, "   |-Window   : %d\n", ntohs(tcph->th_win));
    fprintf(logfile, "   |-Checksum : %d\n", ntohs(tcph->th_sum));
    fprintf(logfile, "   |-UgntOff  : %d\n", ntohs(tcph->th_urp));

    fprintf(logfile , "\nIP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "\nTCP Header\n");
    PrintData(Buffer+iphdrlen, (tcph->th_off & 0xF0)>>2);

    fprintf(logfile , "\nData Payload %d bytes\n\n", Size-tcphdrlen);
}

void print_udp_packet(unsigned char *Buffer , int Size)
{
    udp++;

    print_ip_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ip *iph = (struct ip *)Buffer;
    int iphdrlen = iph->ip_hl*4;

    struct udphdr *udph=(struct udphdr*)(Buffer+iphdrlen);
    int udphdrlen = iphdrlen + sizeof(*udph);

    fprintf(logfile , "UDP Header\n");
    fprintf(logfile , "   |-Header   : %d bytes\n", (int)sizeof(struct udphdr));
    fprintf(logfile , "   |-Src Port : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-DestPort : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Len  : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-Checksum : %d\n" , ntohs(udph->check));

    fprintf(logfile , "\nIP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "\nUDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "\nData Payload %d bytes\n\n", Size-udphdrlen);
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
    icmp++;

    print_ip_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ip *iph = (struct ip *)Buffer;
    int iphdrlen = iph->ip_hl*4;

    unsigned char* icmpdata = Buffer + iphdrlen;
    struct icmp *icmph=(struct icmp*)(Buffer+iphdrlen);

    fprintf(logfile, "ICMP Header\n");

    struct in_addr addr;
    int len = 8;

    if( icmph->icmp_type == ICMP_ECHO ||
        icmph->icmp_type == ICMP_ECHOREPLY ||
        icmph->icmp_type == ICMP_INFO_REQUEST ||
        icmph->icmp_type == ICMP_INFO_REPLY )
    {
        if( icmph->icmp_type == ICMP_ECHO )
            fprintf(logfile, "   |-Echo Request 8\n");
        else if( icmph->icmp_type == ICMP_ECHOREPLY )
            fprintf(logfile, "   |-Echo Reply 0\n");
        else if( icmph->icmp_type == ICMP_INFO_REQUEST )
            fprintf(logfile, "   |-Information Request 15\n");
        else if( icmph->icmp_type == ICMP_INFO_REPLY )
            fprintf(logfile, "   |-Information Reply 16\n");

        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        fprintf(logfile, "   |-ID       : %d\n",ntohs(icmph->icmp_id));
        fprintf(logfile, "   |-Sequence : %d\n",ntohs(icmph->icmp_seq));
    }
    else if( icmph->icmp_type == ICMP_REDIRECT )
    {
        fprintf(logfile, "   |-Redirect 5\n");
        switch( icmph->icmp_code ) {
        case ICMP_REDIR_NET:
            fprintf(logfile, "   |-Code     : Network 0\n");
            break;
        case ICMP_REDIR_HOST:
            fprintf(logfile, "   |-Code     : Host 1\n");
            break;
        case ICMP_REDIR_NETTOS:
            fprintf(logfile, "   |-Code     : Network for TOS 2\n");
            break;
        case ICMP_REDIR_HOSTTOS:
            fprintf(logfile, "   |-Code     : Host for TOS 3\n");
            break;
        default:
            fprintf(logfile, "   |-Code     : Unhandled %d\n",(int)icmph->icmp_code);
            break;
        }
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        fprintf(logfile, "   |-Gateway  : %s\n", inet_ntoa(icmph->icmp_gwaddr) );
    }
    else if( icmph->icmp_type == ICMP_DEST_UNREACH )
    {
        fprintf(logfile, "   |-Destination Unreachable 3\n");

        switch( icmph->icmp_code ) {
        case ICMP_NET_UNREACH:
            fprintf(logfile, "   |-Code     : Destination network unreachable 0\n");
            break;
        case ICMP_HOST_UNREACH:
            fprintf(logfile, "   |-Code     : Destination host unreachable 1\n");
            break;
        case ICMP_PROT_UNREACH:
            fprintf(logfile, "   |-Code     : Destination protocol unreachable 2\n");
            break;
        case ICMP_PORT_UNREACH:
            fprintf(logfile, "   |-Code     : Destination port unreachable 3\n");
            break;
        case ICMP_FRAG_NEEDED:
            fprintf(logfile, "   |-Code     : Fragmentation required, and DF flag set 4\n");
            break;
        case ICMP_SR_FAILED:
            fprintf(logfile, "   |-Code     : Source route failed 5\n");
            break;
        case ICMP_NET_UNKNOWN:
            fprintf(logfile, "   |-Code     : Destination network unknown 6\n");
            break;
        case ICMP_HOST_UNKNOWN:
            fprintf(logfile, "   |-Code     : Destination host unknown 7\n");
            break;
        case ICMP_HOST_ISOLATED:
            fprintf(logfile, "   |-Code     : Source host isolated 8\n");
            break;
        case ICMP_NET_ANO:
            fprintf(logfile, "   |-Code     : Network administratively prohibited 9\n");
            break;
        case ICMP_HOST_ANO:
            fprintf(logfile, "   |-Code     : Host administratively prohibited 10\n");
            break;
        case ICMP_NET_UNR_TOS:
            fprintf(logfile, "   |-Code     : Network unreachable for TOS 11\n");
            break;
        case ICMP_HOST_UNR_TOS:
            fprintf(logfile, "   |-Code     : Host unreachable for TOS 12\n");
            break;
        case ICMP_PKT_FILTERED:
            fprintf(logfile, "   |-Code     : Communication administratively prohibited 13\n");
            break;
        case ICMP_PREC_VIOLATION:
            fprintf(logfile, "   |-Code     : Host Precedence Violation 14\n");
            break;
        case ICMP_PREC_CUTOFF:
            fprintf(logfile, "   |-Code     : Precedence cutoff in effect 15\n");
            break;
        default:
            fprintf(logfile, "   |-Code     : Unhandled %d\n",(int)icmph->icmp_code);
            break;
        }
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        fprintf(logfile, "   |-Next-Hop MTU : %d\n",ntohs(icmph->icmp_nextmtu));
    }
    else if( icmph->icmp_type == ICMP_TIME_EXCEEDED )
    {
        fprintf(logfile, "   |-Time Exceeded 11\n");
        switch( icmph->icmp_code ) {
        case ICMP_EXC_TTL:
            fprintf(logfile, "   |-Code     : Time-to-Live exceeded in transit 0\n");
            break;
        case ICMP_EXC_FRAGTIME:
            fprintf(logfile, "   |-Code     : Fragment reassembly time exceeded 1\n");
            break;
        default:
            fprintf(logfile, "   |-Code     : Unhandled %d\n",(int)icmph->icmp_code);
            break;
        }
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
    }
    else if( icmph->icmp_type == ICMP_PARAMETERPROB )
    {
        fprintf(logfile, "   |-Parameter Problem 12\n");
        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        fprintf(logfile, "   |-Problem Octet : %d\n", (int)icmph->icmp_pptr);
    }
    else if( icmph->icmp_type == ICMP_SOURCE_QUENCH )
    {
        fprintf(logfile, "   |-Source Quench 4\n");
        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
    }
    else if( icmph->icmp_type == ICMP_ADDRESS ||
        icmph->icmp_type == ICMP_ADDRESSREPLY )
    {
        if( icmph->icmp_type == ICMP_ADDRESS )
            fprintf(logfile, "   |-Address Mask Request 17\n");
        else if( icmph->icmp_type == ICMP_ADDRESSREPLY )
            fprintf(logfile, "   |-Address Mask Reply 18\n");
        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        fprintf(logfile, "   |-ID       : %d\n",ntohs(icmph->icmp_id));
        fprintf(logfile, "   |-Sequence : %d\n",ntohs(icmph->icmp_seq));

        if( icmph->icmp_type == ICMP_ADDRESSREPLY ) {
            addr.s_addr = icmph->icmp_mask;
            fprintf(logfile, "   |-AddrMask : %s\n", inet_ntoa(addr) );
        }
    }
    else if( icmph->icmp_type == ICMP_TIMESTAMP ||
        icmph->icmp_type == ICMP_TIMESTAMPREPLY )
    {
        if( icmph->icmp_type == ICMP_TIMESTAMP )
            fprintf(logfile, "   |-Timestamp Request 13\n");
        else if( icmph->icmp_type == ICMP_TIMESTAMPREPLY )
            fprintf(logfile, "   |-Timestamp Reply 14\n");

        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        fprintf(logfile, "   |-ID       : %d\n",ntohs(icmph->icmp_id));
        fprintf(logfile, "   |-Sequence : %d\n",ntohs(icmph->icmp_seq));

        if( Size-iphdrlen-len >= 4 ) {
            fprintf(logfile, "   |-Originate Timestamp : %d\n",htonl(icmph->icmp_otime));
            len += 4;
        }
        if( Size-iphdrlen-len >= 4 ) {
            fprintf(logfile, "   |-Receive Timestamp : %d\n",htonl(icmph->icmp_otime));
            len += 4;
        }
        if( Size-iphdrlen-len >= 4 ) {
            fprintf(logfile, "   |-Transmit Timestamp : %d\n",htonl(icmph->icmp_otime));
            len += 4;
        }
    }
    else if( icmph->icmp_type == ICMP_ROUTERADVERT )
    {
        fprintf(logfile, "   |-Router Advertisement 9\n");
        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
        int num = icmph->icmp_num_addrs;
        fprintf(logfile, "   |-NumAddrs : %d\n",num);
        fprintf(logfile, "   |-AddrSize : %d\n",(int)icmph->icmp_wpa);
        fprintf(logfile, "   |-Lifetime : %d\n",ntohs(icmph->icmp_lifetime));
        for(char i = 0; i < num; i++)
        {
            if( Size-iphdrlen-len < 4) break;
            addr.s_addr = *(u_int32_t*)(icmpdata+len);
            fprintf(logfile, "       |-Router Address %d : %s\n", i, inet_ntoa(addr) );
            len += 4;

            if( Size-iphdrlen-len < 4) break;
            fprintf(logfile, "       |-Prefer Level %d   : %d\n", i, ntohl(*(int32_t*)(icmpdata+len)) );
            len += 4;
        }
    }
    else if( icmph->icmp_type == ICMP_ROUTERSOLICIT )
    {
        fprintf(logfile, "   |-Router Solicitation 10\n");
        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
    }
    else
    {
        fprintf(logfile, "   |-Type     : %d\n",(int)icmph->icmp_type);
        fprintf(logfile, "   |-Code     : %d\n",(int)icmph->icmp_code);
        fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->icmp_cksum));
    }

    fprintf(logfile, "\nIP Header\n");
    PrintData(Buffer, iphdrlen );

    fprintf(logfile, "\nICMP Header %d bytes\n", len);
    PrintData(icmpdata, len);

    fprintf(logfile, "\nData Payload %d bytes\n", Size-iphdrlen-len);
    PrintData(icmpdata+len, Size-iphdrlen-len);
}

void print_igmp_packet( unsigned char* Buffer, int Size )
{
    igmp++;

    print_ip_header(Buffer, Size);

    int ethlen = noeth ? 0 : sizeof(struct ethhdr);
    Buffer += ethlen;
    Size -= ethlen;

    struct ip *iph = (struct ip *)Buffer;
    int iphdrlen = iph->ip_hl*4;

    unsigned char* igmpdata = Buffer + iphdrlen;
    struct igmp *igmph=(struct igmp*)igmpdata;
    int len = IGMP_MINLEN;
    struct in_addr tmpaddr;

    fprintf(logfile, "IGMP Header\n");
    if( igmph->igmp_type && igmph->igmp_type < 9 )
    {
        if( igmph->igmp_type == 0x01 )
            fprintf(logfile, "   |-V0 Create Group Request 0x01\n");
        else if( igmph->igmp_type == 0x02 )
            fprintf(logfile, "   |-V0 Create Group Reply 0x02\n");
        else if( igmph->igmp_type == 0x03 )
            fprintf(logfile, "   |-V0 Join Group Request 0x03\n");
        else if( igmph->igmp_type == 0x04 )
            fprintf(logfile, "   |-V0 Join Group Reply 0x04\n");
        else if( igmph->igmp_type == 0x05 )
            fprintf(logfile, "   |-V0 Leave Group Request 0x05\n");
        else if( igmph->igmp_type == 0x06 )
            fprintf(logfile, "   |-V0 Leave Group Reply 0x06\n");
        else if( igmph->igmp_type == 0x07 )
            fprintf(logfile, "   |-V0 Confirm Group Request 0x07\n");
        else if( igmph->igmp_type == 0x08 )
            fprintf(logfile, "   |-V0 Confirm Group Reply 0x08\n");

        /*  v0 requests */
        if( igmph->igmp_type % 2 )
        {
            if( igmph->igmp_code == 0 )
                fprintf(logfile, "   |-Code       : Public 0\n");
            else if( igmph->igmp_code == 1 )
                fprintf(logfile, "   |-Code       : Private 1\n");
            else
                fprintf(logfile, "   |-Code       : %d\n", (int)igmph->igmp_code);
        }
        else /*  v0 replies */
        {
            if( igmph->igmp_code == 0 )
                fprintf(logfile, "   |-Code       : Granted 0\n");
            else if( igmph->igmp_code == 1 )
                fprintf(logfile, "   |-Code       : Denied (no resources) 1\n");
            else if( igmph->igmp_code == 2 )
                fprintf(logfile, "   |-Code       : Denied (invalid code) 2\n");
            else if( igmph->igmp_code == 3 )
                fprintf(logfile, "   |-Code       : Denied (invalid group address) 3\n");
            else if( igmph->igmp_code == 4 )
                fprintf(logfile, "   |-Code       : Denied (invalid access key.) 4\n");
            else
                fprintf(logfile, "   |-Code       : Pending, retry in this %d seconds\n", (int)igmph->igmp_code);
        }
        fprintf(logfile, "   |-Checksum   : %d\n",ntohs(igmph->igmp_cksum));
        fprintf(logfile, "   |-Identifier : %d\n",ntohl(igmph->igmp_group.s_addr));

        if( (Size-iphdrlen-len) >= 4 ) {
            tmpaddr.s_addr = *(in_addr_t*)(igmpdata + len);
            fprintf(logfile, "   |-GroupAddr  : %s\n",inet_ntoa(tmpaddr) );
            len += 4;
        }

        if( (Size-iphdrlen-len) >= 8 ) {
            tmpaddr.s_addr = *(in_addr_t*)(igmpdata + len);
            fprintf(logfile, "   |-AccessKey  : ");
            for( int8_t i = 0; i < 8; ++i )
                fprintf(logfile, "%.2x ", *(igmpdata+(len++)));
            fprintf(logfile, "\n");
        }
    }
    else if( (igmph->igmp_type == IGMP_MEMBERSHIP_QUERY) )
    {
        fprintf(logfile, "   |-Membership Query 0x11\n");
        if( igmph->igmp_code < 128 )
            fprintf(logfile, "   |-MaxRespTime          : %d\n", (int)igmph->igmp_code);
        else
            fprintf(logfile, "   |-MaxRespTime          : %d.%d\n", (int)(igmph->igmp_code & 0xF), (int)(igmph->igmp_code & 0xF0)>>4);
        fprintf(logfile, "   |-Checksum             : %d\n", ntohs(igmph->igmp_cksum));
        fprintf(logfile, "   |-GroupAddr            : %s\n", inet_ntoa(igmph->igmp_group));

        if( (Size-iphdrlen-len) >= 2 ) {
            u_int8_t var = (0 != (*(igmpdata+len) & 0x08));
            fprintf(logfile, "   |-Suppress Router-Side : %d\n", var);
            var = *(igmpdata+len) & 0x07;
            fprintf(logfile, "   |-Query Robustness     : %d\n", var);
            len += 1;
            var = *(igmpdata+len);
            fprintf(logfile, "   |-Query Interval Code  : %d\n", var);
            len += 1;
        }

        u_int16_t num =  0;
        if( (Size-iphdrlen-len) >= 2 ) {
            num = ntohs(*(uint16_t*)(igmpdata+len));
            fprintf(logfile, "   |-Number of Sources    : %d\n", num);
            len += 2;
        }

        for( int8_t i = 0; i < num; i++ )
        {
            if( (Size-iphdrlen-len) < 4 ) break;
            tmpaddr.s_addr = *(in_addr_t*)(igmpdata+len);
            fprintf(logfile, "        |-Source Address %d : %s\n", i, inet_ntoa(tmpaddr));
            len += 4;
        }
    }
    else if( (igmph->igmp_type == IGMP_V1_MEMBERSHIP_REPORT) ||
             (igmph->igmp_type == IGMP_V2_MEMBERSHIP_REPORT) )
    {
        fprintf(logfile, "   |-V%d Membership Report 0x%.2x\n",
                (IGMP_V1_MEMBERSHIP_REPORT == igmph->igmp_type) ? 1: 2, (int)igmph->igmp_type);
        fprintf(logfile, "   |-MaxRespTime : %d\n", (int)igmph->igmp_code);
        fprintf(logfile, "   |-Checksum    : %d\n", ntohs(igmph->igmp_cksum));
        fprintf(logfile, "   |-GroupAddr   : %s\n", inet_ntoa(igmph->igmp_group) );
    }
    else if( igmph->igmp_type == 0x22 )
    {
        fprintf(logfile, "   |-V3 Membership Report 0x22\n");
        fprintf(logfile, "   |-Checksum    : %d\n",(int)igmph->igmp_cksum);

        u_int16_t num = ntohl(igmph->igmp_group.s_addr)&0x0000FFFF;
        fprintf(logfile, "   |-RecordsNum  : %d\n", num);
        for( int8_t i = 0; i < num; i++ )
        {
            if( (Size-iphdrlen-len) < 4 ) break;

            u_int8_t var = *(igmpdata+len);
            if( var == 4 )
                fprintf(logfile, "       |-%d RecordType : CHANGE_TO_EXCLUDE_MODE 4\n", i);
            else if( var == 3 )
                fprintf(logfile, "       |-%d RecordType : CHANGE_TO_INCLUDE_MODE 3\n", i);
            else if( var == 2 )
                fprintf(logfile, "       |-%d RecordType : MODE_IS_EXCLUDE 2\n", i);
            else if( var == 1 )
                fprintf(logfile, "       |-%d RecordType : MODE_IS_INCLUDE 1\n", i);
            else
                fprintf(logfile, "       |-%d RecordType : %d\n", i, var);

            var = *(igmpdata+len+1); /* aux len */

            u_int16_t nSources = ntohs(*(uint16_t*)(igmpdata+len+2));
            len += 4;

            if( (Size-iphdrlen-len) < 4 ) break;
            tmpaddr.s_addr = *(in_addr_t*)(igmpdata+len);
            fprintf(logfile, "       |-%d Multicast  : %s\n", i, inet_ntoa(tmpaddr));
            fprintf(logfile, "       |-%d SourcesNum : %d\n", i, nSources);
            len += 4;

            for( int8_t c = 0; c < nSources; c++ )
            {
                if( (Size-iphdrlen-len) < 4 ) break;
                tmpaddr.s_addr = *(in_addr_t*)(igmpdata+len);
                fprintf(logfile, "           |-%d Source : %s\n", c, inet_ntoa(tmpaddr));
                len += 4;
            }

            if( (var*4) && ((Size-iphdrlen-len) >= (var*4)) )
            {
                fprintf(logfile, "       |-%d AuxData : ", i);
                for( int8_t j = 0; j < (var*4); j++ )
                    fprintf(logfile, "%.2X ", *(igmpdata+len+j));
                len += var*4;
                fprintf(logfile, "\n");
            }
        }
    }
    else if( igmph->igmp_type == IGMP_DVMRP )
    {
        fprintf(logfile, "   |-DVMRP 0x13\n");
        if( igmph->igmp_code < 128 )
            fprintf(logfile, "   |-MaxRespTime          : %d\n",(int)igmph->igmp_code);
        else
            fprintf(logfile, "   |-MaxRespTime          : %d.%d\n", (int)(igmph->igmp_code & 0xF), (int)(igmph->igmp_code & 0xF0)>>4);
        fprintf(logfile, "   |-Checksum             : %d\n", ntohs(igmph->igmp_cksum));
        len = 4;
    }
    else if( igmph->igmp_type == 0x30 )
    {
        fprintf(logfile, "   |-Multicast Router Advertisement 0x30\n");
        if( igmph->igmp_code < 128 )
            fprintf(logfile, "   |-AdvInterval : %d\n",(int)igmph->igmp_code);
        else
            fprintf(logfile, "   |-AdvInterval : %d.%d\n", (int)(igmph->igmp_code & 0xF), (int)(igmph->igmp_code & 0xF0)>>4);
        fprintf(logfile, "   |-Checksum    : %d\n", ntohs(igmph->igmp_cksum));
        fprintf(logfile, "   |-QryInterval : %d\n", ((igmph->igmp_group.s_addr)&0xFFFF0000)>>8);
        fprintf(logfile, "   |-RobustnsVar : %d\n", ((igmph->igmp_group.s_addr)&0xFFFF));
    }
    else if( (igmph->igmp_type == 0x31) ||
             (igmph->igmp_type == 0x32) )
    {
        fprintf(logfile, "   |-Multicast Router %s 0x%.2x\n",
                (igmph->igmp_type == 0x31) ? "Solicitation" : "Termination",
                (int)igmph->igmp_type);
        fprintf(logfile, "   |-Checksum : %d\n", ntohs(igmph->igmp_cksum));
        len = 4;
    }
    else
    {
        if( igmph->igmp_type == IGMP_PIM )
            fprintf(logfile, "   |-PIM Routing 0x14\n");
        else if( igmph->igmp_type == IGMP_V2_LEAVE_GROUP )
            fprintf(logfile, "   |-Leave-Group 0x17\n");
        else if( igmph->igmp_type == IGMP_TRACE )
            fprintf(logfile, "   |-Traceroute Message 0x15\n");
        else if( igmph->igmp_type == IGMP_MTRACE_RESP )
            fprintf(logfile, "   |-Traceroute Response 0x1e\n");
        else if( igmph->igmp_type == IGMP_MTRACE )
            fprintf(logfile, "   |-MCast Traceroute Message 0x1f\n");
        else
            fprintf(logfile, "   |-Type : 0x%.2x\n",(int)igmph->igmp_type);

        fprintf(logfile, "   |-MaxRespCode : %d\n",(int)igmph->igmp_code);
        fprintf(logfile, "   |-Checksum    : %d\n", ntohs(igmph->igmp_cksum));
        if( (Size-iphdrlen) >= len)
            fprintf(logfile, "   |-GroupAddr   : %s\n", inet_ntoa(igmph->igmp_group));
        else
            len = 4;
    }

    fprintf(logfile, "\nIP Header\n");
    PrintData(Buffer, iphdrlen );

    fprintf(logfile, "\nIGMP Header %d bytes\n", len);
    PrintData(igmpdata, len);

    fprintf(logfile, "\nData Payload %d bytes\n", Size-iphdrlen-len);
    PrintData(igmpdata+len, Size-iphdrlen-len );
}

void PrintData (unsigned char* data , int Size)
{
    if( Size <= 0 )
    {
        fprintf(logfile ,  "\n" );
        return;
    }

    short i, j;
    for(i = 0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %.2X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(logfile , "   "); //extra spaces
            }

            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}

void lookup_arp(struct in_addr& ipaddr, int send_fd)
{
    struct ethhdr ethdr;
    memset(&ethdr, 0, 14);

    unsigned char broad[ETH_ALEN] = {255,255,255,255,255,255};
    memcpy(ethdr.h_dest,broad,ETH_ALEN);
    ethdr.h_proto = htons(ETH_P_ARP);

    struct ether_arp arh;
    arh.ea_hdr.ar_op  = htons(ARPOP_REQUEST);
    arh.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arh.ea_hdr.ar_pro = htons(ETH_P_IP);
    arh.ea_hdr.ar_hln = ETH_ALEN;
    arh.ea_hdr.ar_pln = 4;
    memset(arh.arp_sha, 0, sizeof(arh.arp_sha));
    memset(arh.arp_tha, 0, sizeof(arh.arp_tha));
    memcpy(&(arh.arp_spa[0]), &(ipaddr.s_addr), 4);
    memcpy(&(arh.arp_tpa[0]), &(ipaddr.s_addr), 4);

    unsigned char* buf = (unsigned char*)malloc(14 + sizeof(arh));
    memcpy(buf,&ethdr,14);
    memcpy(buf+14,&arh,sizeof(arh));

    fprintf(logfile, "\n#################################################################\n");
    fprintf(logfile, "Lookup IP address by ARP reqest.\n");
    bool store = noeth;
    if( store ) noeth = false;

    print_arp_header( buf, 14 + sizeof(arh) );
    noeth = store;
    free(buf);

    memcpy(&fromAddr, &servAddr, sizeof(fromAddr));
    fromAddr.sll_protocol = htons(ETH_P_ARP);
    int data_size = sendto(send_fd, buf, 14 + sizeof(arh), 0, (sockaddr*)&fromAddr, sizeof fromAddr);
    if( data_size < 0 )
    {
        perror("::sendto error\n");
    }
}
