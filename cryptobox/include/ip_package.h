#ifndef __ip_package_h__
#define __ip_package_h__

#include "raw_message.h"

#ifndef WIN32
    #include <netinet/in.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>
#else
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    #define IP_MF      0x2000   /* more fragments flag */
    #define IP_DF      0x4000   /* dont fragment flag */
#endif


/*******************************************************/
struct ip_header 
{
    u8  vhl;
    u8  type_of_service;
    u16 total_length;
    u16 id;
    u16 frame_offset;
    u8  time_to_live;
    u8  protocol;
    u16 checksum;
    struct in_addr source_address;
    struct in_addr dest_address;
};

/*******************************************************/

#ifndef	TH_FIN
    #define TH_FIN  0x01
#endif
#ifndef	TH_SYN
    #define TH_SYN  0x02
#endif
#ifndef	TH_RST
    #define TH_RST  0x04
#endif
#ifndef	TH_PUSH
    #define TH_PUSH 0x08
#endif
#ifndef	TH_ACK
    #define TH_ACK  0x10
#endif
#ifndef	TH_URG
    #define TH_URG  0x20
#endif

struct tcp_header {
    u16 th_sport;
    u16 th_dport;
    u32 th_seq;
    u32 th_ack;
    u8  th_doff;
    u8  th_flags;
    u16 th_win;
    u16 th_sum;
    u16 th_urp;
};

/*******************************************************/
struct udp_header {
    u16 uh_sport;
    u16 uh_dport;
    s16 uh_ulen;
    u16 uh_sum;
};

/*******************************************************/
#ifdef WIN32

#define ICMP_ECHOREPLY		0   /* Echo Reply               */
#define ICMP_DEST_UNREACH	3   /* Destination Unreachable  */
#define ICMP_SOURCE_QUENCH	4   /* Source Quench            */
#define ICMP_REDIRECT		5   /* Redirect (change route)  */
#define ICMP_ECHO           8   /* Echo Request             */
#define	ICMP_ROUTERADVERT   9   /* Router advertisement */
#define	ICMP_ROUTERSOLICIT  10  /* Router solicitation */
#define ICMP_TIME_EXCEEDED  11  /* Time Exceeded            */
#define ICMP_PARAMETERPROB  12  /* Parameter Problem        */
#define ICMP_TIMESTAMP      13  /* Timestamp Request        */
#define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply          */
#define ICMP_INFO_REQUEST   15  /* Information Request      */
#define ICMP_INFO_REPLY     16  /* Information Reply        */
#define ICMP_ADDRESS        17  /* Address Mask Request     */
#define ICMP_ADDRESSREPLY   18  /* Address Mask Reply       */

/*  Codes for UNREACH   */
#define ICMP_NET_UNREACH    0   /* Network Unreachable		*/
#define ICMP_HOST_UNREACH   1   /* Host Unreachable		*/
#define ICMP_PROT_UNREACH   2   /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH   3   /* Port Unreachable		*/
#define ICMP_FRAG_NEEDED    4   /* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED      5   /* Source Route failed		*/
#define ICMP_NET_UNKNOWN    6
#define ICMP_HOST_UNKNOWN   7
#define ICMP_HOST_ISOLATED  8
#define ICMP_NET_ANO        9
#define ICMP_HOST_ANO       10
#define ICMP_NET_UNR_TOS    11
#define ICMP_HOST_UNR_TOS   12
#define ICMP_PKT_FILTERED   13  /* Packet filtered */
#define ICMP_PREC_VIOLATION 14  /* Precedence violation */
#define ICMP_PREC_CUTOFF    15  /* Precedence cut off */

/*  Codes for REDIRECT  */
#define ICMP_REDIR_NET      0   /* Redirect Net			*/
#define ICMP_REDIR_HOST     1   /* Redirect Host		*/
#define ICMP_REDIR_NETTOS   2   /* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS  3   /* Redirect Host for TOS	*/

/*  Codes for TIME_EXCEEDED */
#define ICMP_EXC_TTL        0   /* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME   1   /* Fragment Reass time exceeded	*/

struct icmphdr
{
    u8 type;
    u8 code;
    u16 checksum;
    union {
        struct {
            u16 id;
            u16 sequence;
        } echo;
        u32 gateway;
        struct {
            u16 __unused;
            u16 mtu;
        } frag;
    } un;
};

struct icmp_ra_addr
{
    u32 ira_addr;
    u32 ira_preference;
};

struct icmp
{
    u8  icmp_type;    /* type of message, see below */
    u8  icmp_code;    /* type sub code */
    u16 icmp_cksum;   /* ones complement checksum of struct */
    union {
        u8 ih_pptr;                 /*  ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;   /*  gateway address */
        struct ih_idseq {           /*  echo datagram */
            u16 icd_id;
            u16 icd_seq;
        } ih_idseq;
        u32 ih_void;

        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu {
            u16 ipm_void;
            u16 ipm_nextmtu;
        } ih_pmtu;

        struct ih_rtradv {
            u8  irt_num_addrs;
            u8  irt_wpa;
            u16 irt_lifetime;
        } ih_rtradv;
    } icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
    union {
        struct {
            u32 its_otime;
            u32 its_rtime;
            u32 its_ttime;
        } id_ts;
        struct {
        #ifdef WIN32
            struct ip_header idi_ip;
        #else
            struct ip idi_ip;
        #endif
            /* options and then 64 bits of data */
        } id_ip;
        struct icmp_ra_addr id_radv;
        u32 id_mask;
        u8  id_data[1];
    } icmp_dun;
#define icmp_otime  icmp_dun.id_ts.its_otime
#define icmp_rtime  icmp_dun.id_ts.its_rtime
#define icmp_ttime  icmp_dun.id_ts.its_ttime
#define icmp_ip     icmp_dun.id_ip.idi_ip
#define icmp_radv   icmp_dun.id_radv
#define icmp_mask   icmp_dun.id_mask
#define icmp_data   icmp_dun.id_data
};

/*******************************************************/

#define IGMP_MEMBERSHIP_QUERY           0x11    /* From RFC1112 */
#define IGMP_V1_MEMBERSHIP_REPORT       0x12    /* Ditto */
#define IGMP_DVMRP                      0x13    /* DVMRP routing */
#define IGMP_PIM                        0x14    /* PIM routing */
#define IGMP_TRACE                      0x15
#define IGMP_V2_MEMBERSHIP_REPORT       0x16    /* V2 version of 0x11 */
#define IGMP_V2_LEAVE_GROUP             0x17
#define IGMPV3_HOST_MEMBERSHIP_REPORT   0x22    /* V3 version of 0x11 */
#define IGMP_MTRACE_RESP                0x1e
#define IGMP_MTRACE                     0x1f

struct igmp {
    u8  igmp_type;
    u8  igmp_code;
    u16 igmp_cksum;
    struct in_addr igmp_group;
};
#endif

/*******************************************************/
/*  IPPackage implementation in RawMessage inheritance */
class IPPackage : public RawMessage
{
    friend class IPSplitter;
    friend class EthernetAdapter;

public:

    IPPackage( const RawMessage& ipPackage );
    virtual ~IPPackage();

    /*  Casts Message to IPPackage object without copying with IP header checking  */
    static IPPackage* castToIP( const u8* pBuffer, u32 bufferSize );
    static inline IPPackage* castToIP( const Message& message );

    inline IPPackage& operator =(const IPPackage& right);
    inline std::string getSrcAddress( void ) const;
    inline std::string getDestAddress( void ) const;
    inline u32 getSrcIP( void ) const;
    inline u32 getDestIP( void ) const;
    inline u16 getIdentifier( void ) const;
    inline u16 getFullLen( void ) const;
    inline u16 getChecksum( void ) const;
    inline u8  getServiceType( void ) const;
    inline u8  getTTL( void ) const;
    inline u8  getTransport( void ) const;
    inline const u8* getExtraHdr( void ) const;
    inline u16 getFragmentation( u16* flags ) const;

    /*  linked identifiers for transport */
    inline void getTcpPortNumbers( u16* srcPort, u16* destPort ) const;
    inline void getUdpPortNumbers( u16* srcPort, u16* destPort ) const;
    inline u16  getIcmpRequestId(u16* seqNum = NULL) const;
    inline u16  getIcmpResponseId(u16* seqNum = NULL) const;

    /*  package creation */
    inline void setData( const u8* buffer, u16 len );
    inline void setSrcAddress( const std::string& srcIP );
    inline void setDestAddress( const std::string& destIP );
    inline void setIdentifier( u16 id );
    inline void setChecksum( u16 chksm );
    inline void setServiceType( u8 srvtype );
    inline void setTTL( u8 ttl );
    inline void setTransport( u8 proto );
    inline void setFragmentation( u16 offset, u16 flag );

    virtual void setDataLen(u32)
    { assert(!"IPPackage setDataLen Should not used!"); }

    virtual void setId(u64)
    { assert(!"IPPackage setId Should not used!"); }

    virtual void setMagicQWord(u64)
    { assert(!"IPPackage setMagicQWord Should not be used!"); }

protected:
    IPPackage();

    virtual void setType( void )
    { type_ = type_IP; }

    inline void check_header( void ) {
        if( NULL == header_ ) {
            header_ = (struct ip_header*)buffer_;
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            headerLen_ = (header_->vhl & 0x0F) << 2;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            headerLen_ = (header_->vhl & 0xF0) >> 2;
        #endif
        }
    }

    struct ip_header* header_;
};
typedef std::vector<IPPackage> IPPackagesT;

/**********************************************************************/
inline IPPackage* IPPackage::castToIP( const Message& message ) 
{
    return castToIP( message.get(), message.size() );
}

inline IPPackage& IPPackage::operator =(const IPPackage& right)
{
    *(RawMessage*)this = right;
    header_  = (struct ip_header*)buffer_;
    return *this;
}

inline u16 IPPackage::getIdentifier() const
{ return ntohs( header_->id ); }

inline u16 IPPackage::getChecksum() const
{ return ntohs( header_->checksum ); }

inline std::string IPPackage::getSrcAddress() const
{ return inet_ntoa( header_->source_address ); }

inline std::string IPPackage::getDestAddress() const
{ return inet_ntoa( header_->dest_address ); }

inline u32 IPPackage::getSrcIP( void ) const
{ return header_->source_address.s_addr; }

inline u32 IPPackage::getDestIP( void ) const
{ return header_->dest_address.s_addr; }

inline u16 IPPackage::getFullLen() const
{ return ntohs( header_->total_length ); }

inline u8 IPPackage::getTTL() const
{ return header_->time_to_live; }

inline u8 IPPackage::getTransport() const
{ return header_->protocol; }

inline u16 IPPackage::getFragmentation( u16* flags ) const
{
    *flags = header_->frame_offset & (IP_MF|IP_DF);
    return ntohs(header_->frame_offset & IP_OFFMASK);
}

inline u8 IPPackage::getServiceType() const
{ return header_->type_of_service; }

inline const u8* IPPackage::getExtraHdr() const {
    if( headerLen_ - sizeof(struct ip_header) == 0 )
        return NULL;
    return buffer_ + sizeof(struct ip_header);
}

inline void IPPackage::setData( const u8* buffer, u16 len )
{
    set_protected_using(0);
    reserve( len + (headerLen_ ? headerLen_ : sizeof(struct ip_header)) );
    check_header();
    memcpy( buffer_+headerLen_, buffer, len );
    dataLen_ = len;
    header_->total_length = htons( len + headerLen_ );
}

inline void IPPackage::setSrcAddress( const std::string& srcIP )
{
    check_header();
#ifdef WIN32
    header_->source_address.S_un.S_addr = inet_addr( srcIP.c_str() );
#else
    header_->source_address.s_addr = inet_addr( srcIP.c_str() );
#endif
}

inline void IPPackage::setDestAddress( const std::string& dstIP )
{
    check_header();
#ifdef WIN32
    header_->dest_address.S_un.S_addr = inet_addr( dstIP.c_str() );
#else
    header_->dest_address.s_addr = inet_addr( dstIP.c_str() );
#endif
}

inline void IPPackage::setIdentifier( u16 id )
{
    check_header();
    header_->id = htons( id );
}

inline void IPPackage::setChecksum( u16 chksm )
{
    check_header();
    header_->checksum = htons( chksm );
}

inline void IPPackage::setServiceType( u8 srvtype )
{
    check_header();
    header_->type_of_service = srvtype;
}

inline void IPPackage::setTTL( u8 ttl )
{
    check_header();
    header_->time_to_live = ttl;
}

inline void IPPackage::setTransport( u8 proto )
{
    check_header();
    header_->protocol = proto;
}

inline void IPPackage::setFragmentation( u16 offset, u16 flag )
{
    check_header();
    header_->frame_offset = htons(offset) | flag;
}

inline void IPPackage::getTcpPortNumbers( u16* srcPort, u16* destPort ) const
{
    if( (header_->protocol == IPPROTO_TCP) && dataLen_ )
    {
        const tcp_header* tcphdr = (const tcp_header*)(buffer_+headerLen_);
        *srcPort  = ntohs(tcphdr->th_sport);
        *destPort = ntohs(tcphdr->th_dport);
    }
}

inline void IPPackage::getUdpPortNumbers( u16* srcPort, u16* destPort ) const
{
    if( (header_->protocol == IPPROTO_UDP) && dataLen_ )
    {
        const udp_header* udphdr = (const udp_header*)(buffer_+headerLen_);
        *srcPort = ntohs(udphdr->uh_sport);
        *destPort = ntohs(udphdr->uh_dport);
    }
}

inline u16 IPPackage::getIcmpRequestId(u16* seqNum) const
{
    if( (header_->protocol == IPPROTO_ICMP) && dataLen_ )
    {
        const struct icmp* icmph = (const struct icmp*)(buffer_+headerLen_);
        if( icmph->icmp_type == ICMP_ECHO ||
            icmph->icmp_type == ICMP_INFO_REQUEST ||
            icmph->icmp_type == ICMP_ADDRESS ||
            icmph->icmp_type == ICMP_TIMESTAMP )
        {
            if( seqNum )
                *seqNum = ntohs(icmph->icmp_seq);
            return ntohs(icmph->icmp_id);
        }
    }
    return 0;
}

inline u16 IPPackage::getIcmpResponseId(u16* seqNum) const
{
    if( (header_->protocol == IPPROTO_ICMP) && dataLen_ )
    {
        const struct icmp* icmph = (const struct icmp*)(buffer_+headerLen_);
        if( icmph->icmp_type == ICMP_ECHOREPLY ||
            icmph->icmp_type == ICMP_INFO_REPLY ||
            icmph->icmp_type == ICMP_ADDRESSREPLY ||
            icmph->icmp_type == ICMP_TIMESTAMPREPLY )
        {
            if( seqNum )
                *seqNum = ntohs(icmph->icmp_seq);
            return ntohs(icmph->icmp_id);
        }
    }
    return 0;
}

/**************************************************************************/
/*  Splitter will be used when several IP packages in the one recv buffer */
class IPSplitter : public SplitRawBufferToMessagesBase
{
friend class IPPackage;
public:
    IPSplitter( bool onSend );
    virtual ~IPSplitter();

    /*  Search for the packages in the buffer.
        @Returns the number of packages found.
    */
    virtual u16 operator()( const u8* pBuffer,
                            i32 bufferSize,
                            RawMessagesT* packages ) const;

    /*  Returns true when splitter working with ethernet frames */
    virtual bool isEthernetSplitter(void ) const
    { return false; }

private:
    bool onSend_;
};


/**/
#endif /* __ip_package_h__ */
