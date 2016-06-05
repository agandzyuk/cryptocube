#ifndef __ethernet_frame_h__
#define __ethernet_frame_h__

#include "raw_message.h"

#ifndef WIN32
    #include <stdio.h>
    #include <netinet/if_ether.h>
#else
    /*  IEEE 802.3 Ethernet magic constants. The frame sizes omit the preamble
        and FCS/CRC (frame check sequence)
    */
    #define ETH_ALEN        6               /* Octets in one ethernet addr     */
    #define ETH_HLEN        14              /* Total octets in header.     */
    #define ETH_ZLEN        60              /* Min. octets in frame sans FCS */
    #define ETH_DATA_LEN    1500            /* Max. octets in payload     */
    #define ETH_FRAME_LEN   1514            /* Max. octets in frame sans FCS */

    /*  These are the defined Ethernet Protocol ID's */

    #define ETH_P_LOOP      0x0060          /* Ethernet Loopback packet     */
    #define ETH_P_PUP       0x0200          /* Xerox PUP packet             */
    #define ETH_P_PUPAT     0x0201          /* Xerox PUP Addr Trans packet  */
    #define ETH_P_IP        0x0800          /* Internet Protocol packet     */
    #define ETH_P_X25       0x0805          /* CCITT X.25                   */
    #define ETH_P_ARP       0x0806          /* Address Resolution packet    */
    #define ETH_P_BPQ    0x08FF             /* G8BPQ AX.25 Ethernet Packet  [ NOT AN OFFICIALLY REGISTERED ID ] */
    #define ETH_P_IEEEPUP   0x0a00          /* Xerox IEEE802.3 PUP packet   */
    #define ETH_P_IEEEPUPAT 0x0a01          /* Xerox IEEE802.3 PUP Addr Trans packet */
    #define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
    #define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
    #define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
    #define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
    #define ETH_P_LAT       0x6004          /* DEC LAT                      */
    #define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
    #define ETH_P_CUST      0x6006          /* DEC Customer use             */
    #define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
    #define ETH_P_RARP      0x8035          /* Reverse Addr Res packet      */
    #define ETH_P_ATALK     0x809B          /* Appletalk DDP                */
    #define ETH_P_AARP      0x80F3          /* Appletalk AARP               */
    #define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
    #define ETH_P_IPX       0x8137          /* IPX over DIX                 */
    #define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */
    #define ETH_P_WCCP      0x883E          /* Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt */
    #define ETH_P_PPP_DISC  0x8863          /* PPPoE discovery messages     */
    #define ETH_P_PPP_SES   0x8864          /* PPPoE session messages       */
    #define ETH_P_MPLS_UC   0x8847          /* MPLS Unicast traffic         */
    #define ETH_P_MPLS_MC   0x8848          /* MPLS Multicast traffic       */
    #define ETH_P_ATMMPOA   0x884c          /* MultiProtocol Over ATM       */
    #define ETH_P_ATMFATE   0x8884          /* Frame-based ATM Transport over Ethernet */
    #define ETH_P_AOE       0x88A2          /* ATA over Ethernet            */

    /*  Non DIX types. Won't clash for 1500 types. */
    #define ETH_P_802_3     0x0001          /* Dummy type for 802.3 frames  */
    #define ETH_P_AX25      0x0002          /* Dummy protocol id for AX.25  */
    #define ETH_P_ALL       0x0003          /* Every packet (be careful!!!) */
    #define ETH_P_802_2     0x0004          /* 802.2 frames                 */
    #define ETH_P_SNAP      0x0005          /* Internal only                */
    #define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
    #define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
    #define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
    #define ETH_P_LOCALTALK 0x0009          /* Localtalk pseudo type        */
    #define ETH_P_PPPTALK   0x0010          /* Dummy type for Atalk over PPP*/
    #define ETH_P_TR_802_2  0x0011          /* 802.2 frames                 */
    #define ETH_P_MOBITEX   0x0015          /* Mobitex (kaz@cafe.net)       */
    #define ETH_P_CONTROL   0x0016          /* Card specific control frames */
    #define ETH_P_IRDA      0x0017          /* Linux-IrDA                   */
    #define ETH_P_ECONET    0x0018          /* Acorn Econet                 */
    #define ETH_P_HDLC      0x0019          /* HDLC frames                  */
    #define ETH_P_ARCNET    0x001A          /* 1A for ArcNet :-)            */

    struct ethhdr {
        u8  h_dest[ETH_ALEN];
        u8  h_source[ETH_ALEN];
        u16 h_proto;
    };
#endif

/*******************************************************/
/*  EthernetFrame implementation in RawMessage inheritance */
class EthernetFrame : public RawMessage
{
    friend class EthernetAdapter;
    friend class EthSplitter;
public:
    enum Type
    {
        EthNoHdr = 0,
        EthOther = 16,
        EthIP    = ETH_P_IP,
        EthIP6   = ETH_P_IPV6,
        EthARP   = ETH_P_ARP,
    };

    EthernetFrame( const RawMessage& ethFrame );
    virtual ~EthernetFrame();

    /*  Casts Message to EthernetFrame object without copying with header checking  */
    static EthernetFrame* castToEthFrame( const u8* pBuffer, u32 bufferSize );
    static inline EthernetFrame* castToEthFrame( const Message& message );

    inline EthernetFrame& operator =(const EthernetFrame& right);
    inline u16 getEthernetType( void ) const;

    inline std::string getDestMacAddress( void ) const;
    inline std::string getSrcMacAddress( void ) const;
    inline const u8* getDestMac( void ) const;
    inline const u8* getSrcMac( void ) const;
    inline u16 getProtocolType( void ) const;

    /*  package creation */
    inline void setData( const u8* buffer, u16 len );
    inline void setSrcMacAddress( const std::string& srcMac );
    inline void setDestMacAddress( const std::string& destMac );
    inline void setSrcMac( u8 const srcMac[ETH_ALEN] );
    inline void setDestMac( u8 const destMac[ETH_ALEN] );
    inline void setProtocolType( const u16 proto );

    inline void setDataLen(u32)
    { assert(!"EthernetFrame setDataLen Should not used!"); }

    virtual void setId(u64)
    { assert(!"EthernetFrame setId Should not used!"); }

    virtual void setMagicQWord(u64)
    { assert(!"RawMessage setMagicQWord should not be used!"); }

protected:
    EthernetFrame();

    virtual void setType( void )
    { type_ = type_Eth; }

    inline void check_header( void ) {
        if( NULL == header_ ) {
            header_ = (struct ethhdr*)buffer_;
            headerLen_ = sizeof(struct ethhdr);
        }
    }

    struct ethhdr* header_;
    u16 ethernetType_;
};
typedef std::vector<EthernetFrame> EthernetFramesT;

/**********************************************************************/
inline EthernetFrame* EthernetFrame::castToEthFrame( const Message& message ) 
{
    return castToEthFrame( message.get(), message.size() );
}

inline EthernetFrame& EthernetFrame::operator =(const EthernetFrame& right)
{
    *static_cast<RawMessage*>(this) = right;
    ethernetType_ = right.getEthernetType();
    header_ = (struct ethhdr*)buffer_;
    return *this;
}

inline u16 EthernetFrame::getEthernetType() const
{ return ethernetType_; }

inline std::string EthernetFrame::getDestMacAddress() const
{ 
    s8 buf[] = "00:00:00:00:00:00";
    const u8* a = &(header_->h_dest[0]);
    sprintf(buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}

inline std::string EthernetFrame::getSrcMacAddress() const
{ 
    s8 buf[] = "00:00:00:00:00:00";
    const u8* a = &(header_->h_source[0]);
    sprintf(buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}

inline const u8* EthernetFrame::getDestMac() const
{
    return &(header_->h_dest[0]);
}

inline const u8* EthernetFrame::getSrcMac() const
{
    return &(header_->h_source[0]);
}

inline u16 EthernetFrame::getProtocolType() const
{
    return ntohs(header_->h_proto);
}


inline void EthernetFrame::setData( const u8* buffer, u16 len )
{
    set_protected_using(0);
    headerLen_ = sizeof(struct ethhdr);
    reserve( len + headerLen_ );
    header_ = (struct ethhdr*)buffer_;
    memcpy( buffer_+headerLen_, buffer, len );
    dataLen_ = len;
}

inline void EthernetFrame::setDestMacAddress( const std::string& destMac )
{
    check_header();

    if( !destMac.empty() && (
        (destMac.length() != strlen("00:00:00:00:00:00")) ||
        (destMac[2] != ':') || (destMac[5] != ':') || (destMac[8] != ':') || (destMac[11] != ':') || (destMac[14] != ':') 
      ) )
    {
        assert( !"EthernetFrame::setDestMac Error setting the destination MAC address!" );
        throw Exception("Ethernet header data: error setting the destination MAC address.");
    }

    memset(header_->h_dest, 0, sizeof( header_->h_dest ));
    if( !destMac.empty() ) {
        u8* a = &(header_->h_dest[0]);
        sscanf(destMac.c_str(), "%x:%x:%x:%x:%x:%x", (i32*)(a), (i32*)(a+1), (i32*)(a+2), (i32*)(a+3), (i32*)(a+4), (i32*)(a+5));
    }
}

inline void EthernetFrame::setSrcMacAddress( const std::string& srcMac )
{
    check_header();

    if( !srcMac.empty() && (
        (srcMac.length() != strlen("00:00:00:00:00:00")) ||
        (srcMac[2] != ':') || (srcMac[5] != ':') || (srcMac[8] != ':') || (srcMac[11] != ':') || (srcMac[14] != ':') 
      ) )
    {
        assert( !"EthernetFrame::setSrcMac Error setting the source MAC address!" );
        throw Exception("Ethernet header data: error setting the source MAC address.");
    }

    memset(header_->h_source, 0, sizeof( header_->h_source ));
    if( !srcMac.empty() ) {
        u8* a = &(header_->h_source[0]);
        sscanf(srcMac.c_str(), "%x:%x:%x:%x:%x:%x", (i32*)(a), (i32*)(a+1), (i32*)(a+2), (i32*)(a+3), (i32*)(a+4), (i32*)(a+5));
    }
}

inline void EthernetFrame::setSrcMac( u8 const srcMac[ETH_ALEN] )
{
    check_header();
    memcpy(header_->h_source, srcMac, ETH_ALEN);
}

inline void EthernetFrame::setDestMac( u8 const destMac[ETH_ALEN] )
{
    check_header();
    memcpy(header_->h_dest, destMac, ETH_ALEN);
}

inline void EthernetFrame::setProtocolType( u16 proto )
{
    check_header();
    header_->h_proto = htons(proto);
}

/**************************************************************************/
/*  Splitter will be used when several Ethernet packages in the one recv buffer */
class EthSplitter : public SplitRawBufferToMessagesBase
{
    friend class EthernetFrame;
public:
    EthSplitter( bool onSend );
    virtual ~EthSplitter();

    /*  Search for the packages in the buffer.
        @Returns the number of packages found.
    */
    virtual u16 operator()( const u8* pBuffer,
                            i32 bufferSize,
                            RawMessagesT* frames ) const;

    /*  Returns true when splitter working with ethernet frames */
    virtual bool isEthernetSplitter( void ) const
    { return true; }

private:
    bool onSend_;
};


/**/
#endif /* __ethernet_frame_h__ */
