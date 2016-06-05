#ifndef __arp_package_h__
#define __arp_package_h__

#include "ethernet_frame.h"

#ifdef WIN32
    struct arphdr {
        u16 ar_hrd;                 /* format of hardware address */
    #define ARPHRD_ETHER    1       /* ethernet hardware address */
        u16 ar_pro;                 /* format of protocol address */
        u8  ar_hln;                 /* length of hardware address */
        u8  ar_pln;                 /* length of protocol address */
        u16 ar_op;                  /* one of: */
    #define ARPOP_REQUEST   1       /* request to resolve address */
    #define ARPOP_REPLY     2       /* response to previous request */
    #define ARPOP_RREQUEST  3       /* RARP request.  */
    #define ARPOP_RREPLY    4       /* RARP reply.  */
    #define ARPOP_InREQUEST 8       /* InARP request.  */
    #define ARPOP_InREPLY   9       /* InARP reply.  */
    #define ARPOP_NAK       10      /* (ATM)ARP NAK.  */
    };

    struct ether_arp {
        struct arphdr ea_hdr;       /* fixed-size header */
        u8  arp_sha[6];             /* sender hardware address */
        u8  arp_spa[4];             /* sender protocol address */
        u8  arp_tha[6];             /* target hardware address */
        u8  arp_tpa[4];             /* target protocol address */
    };

    /*  ARP ioctl request   */
    struct arpreq {
        struct sockaddr arp_pa;     /* protocol address */
        struct sockaddr arp_ha;     /* hardware address */
        i32    arp_flags;           /* flags */
    };

    /*  arp_flags and at_flags field values */
    #define ATF_INUSE       0x01    /* entry in use */
    #define ATF_COM         0x02    /* completed entry (enaddr valid) */
    #define ATF_PERM        0x04    /* permanent entry */
    #define ATF_PUBL        0x08    /* publish entry (respond for other host) */
    #define ATF_USETRAILERS 0x10    /* has requested trailers */

#endif

/*******************************************************/
/*  ARPPackage implementation in RawMessage inheritance */
class ARPPackage : public RawMessage
{
    friend class EthernetAdapter;
    friend class EthSplitter;

public:
    ARPPackage( const RawMessage& arpPackage );
    virtual ~ARPPackage();

    /*  Casts Message to ARPPackage object without copying with ARP header checking  */
    static ARPPackage* castToARP( const u8* pBuffer, u32 bufferSize );
    static inline ARPPackage* castToARP( const Message& message );

    inline ARPPackage& operator =(const ARPPackage& right);

    inline u16 getHWAddressFormat( void ) const;
    inline u16 getProtoAddressFormat( void ) const;
    inline u8  getHWAddressLen( void ) const;
    inline u8  getProtoAddressLen( void ) const;
    inline u16 getOption( void ) const;

    inline const u8* getSenderHW( void ) const;
    inline const u8* getSenderProto( void ) const;
    inline const u8* getTargetHW( void ) const;
    inline const u8* getTargetProto( void ) const;

    inline std::string getSenderHWAddress( void ) const;
    inline std::string getSenderProtoAddress( void ) const;
    inline std::string getTargetHWAddress( void ) const;
    inline std::string getTargetProtoAddress( void ) const;

    /*  package creation */
    inline void setData( const u8* buffer, u16 len );

    inline void setHWAddressFormat( u16 format );
    inline void setProtoAddressFormat( u16 format );
    inline void setHWAddressLen( u8 len );
    inline void setProtoAddressLen( u8 len );
    inline void setOption( u16 opt );

    inline void setSenderHW( u8 const arp_sha[6] );
    inline void setSenderProto( u8 const arp_spa[4] );
    inline void setTargetHW( u8 const arp_tha[6] );
    inline void setTargetProto( u8 const arp_tpa[4] );

    inline void setSenderHWAddress( const std::string& hwAddr );
    inline void setSenderProtoAddress( const std::string& protoAddr );
    inline void setTargetHWAddress( const std::string& hwAddr );
    inline void setTargetProtoAddress( const std::string& protoAddr );

    virtual void setDataLen(u32)
    { assert(!"ARPPackage setDataLen should not used!"); }

    virtual void setId(u64)
    { assert(!"ARPPackage setId should not used!"); }

    virtual void setMagicQWord(u64)
    { assert(!"ARPPackage setMagicQWord should not be used!"); }

protected:
    ARPPackage();

    struct ether_arp* header_;

    virtual void setType( void )
    { type_ = type_ARP; }

    inline void check_header( void ) {
        if( NULL == header_ ) {
            header_ = (struct ether_arp*)buffer_;
            headerLen_ = sizeof(struct ether_arp);
        }
    }
};
typedef std::vector<ARPPackage> ARPPackagesT;

/**********************************************************************/
inline ARPPackage* ARPPackage::castToARP( const Message& message ) 
{
    return castToARP( message.get(), message.size() );
}

inline ARPPackage& ARPPackage::operator =(const ARPPackage& right)
{
    *static_cast<RawMessage*>(this) = right;
    header_ = (struct ether_arp*)buffer_;
    return *this;
}

inline u16 ARPPackage::getHWAddressFormat() const
{ return ntohs( header_->ea_hdr.ar_hrd ); }

inline u16 ARPPackage::getProtoAddressFormat() const
{ return ntohs( header_->ea_hdr.ar_pro ); }

inline u8 ARPPackage::getHWAddressLen() const
{ return header_->ea_hdr.ar_hln; }

inline u8 ARPPackage::getProtoAddressLen() const
{ return header_->ea_hdr.ar_pln; }

inline u16 ARPPackage::getOption() const
{ return ntohs( header_->ea_hdr.ar_op ); }


inline const u8* ARPPackage::getSenderHW() const
{ return header_->arp_sha; }

inline const u8* ARPPackage::getSenderProto() const
{ return header_->arp_spa; }

inline const u8* ARPPackage::getTargetHW() const
{ return header_->arp_tha; }

inline const u8* ARPPackage::getTargetProto() const
{ return header_->arp_tpa; }

inline std::string ARPPackage::getSenderHWAddress() const
{
    s8 buf[] = "00:00:00:00:00:00";
    const u8* a = &(header_->arp_sha[0]);
    sprintf(buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}

inline std::string ARPPackage::getSenderProtoAddress() const
{
    s8 buf[] = "000.000.000.000";
    const u8* a = &(header_->arp_spa[0]);
    sprintf(buf, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
    return buf;
}

inline std::string ARPPackage::getTargetHWAddress() const
{
    s8 buf[] = "00:00:00:00:00:00";
    const u8* a = &(header_->arp_tha[0]);
    sprintf(buf, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}

inline std::string ARPPackage::getTargetProtoAddress() const
{
    s8 buf[] = "000.000.000.000";
    const u8* a = &(header_->arp_tpa[0]);
    sprintf(buf, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
    return buf;
}

inline void ARPPackage::setData( const u8* buffer, u16 len )
{
    set_protected_using(0);
    headerLen_ = sizeof(struct ether_arp);
    reserve( len + headerLen_ );
    header_ = (struct ether_arp*)buffer_;
    memcpy( buffer_+headerLen_, buffer, len );
    dataLen_ = len;
}

inline void ARPPackage::setHWAddressFormat( u16 format )
{
    check_header();
    header_->ea_hdr.ar_hrd = htons( format );
}

inline void ARPPackage::setProtoAddressFormat( u16 format )
{
    check_header();
    header_->ea_hdr.ar_pro = htons( format );
}

inline void ARPPackage::setHWAddressLen( u8 len )
{
    check_header();
    header_->ea_hdr.ar_hln = len;
}

inline void ARPPackage::setProtoAddressLen( u8 len )
{
    check_header();
    header_->ea_hdr.ar_pln = len;
}

inline void ARPPackage::setOption( u16 opt )
{
    check_header();
    header_->ea_hdr.ar_op = htons( opt );
}

inline void ARPPackage::setSenderHW( u8 const arp_sha[6] )
{
    check_header();
    memcpy(header_->arp_sha, arp_sha, 6 );
}

inline void ARPPackage::setSenderProto( u8 const arp_spa[4] )
{
    check_header();
    memcpy(header_->arp_spa, arp_spa, 4 );
}

inline void ARPPackage::setTargetHW( u8 const arp_tha[6] )
{
    check_header();
    memcpy(header_->arp_tha, arp_tha, 6 );
}

inline void ARPPackage::setTargetProto( u8 const arp_tpa[4] )
{
    check_header();
    memcpy(header_->arp_tpa, arp_tpa, 4 );
}


inline void ARPPackage::setSenderHWAddress( const std::string& hwAddr )
{
    check_header();

    if( !hwAddr.empty() && ( 
        (hwAddr.length() != strlen("00:00:00:00:00:00")) ||
        (hwAddr[2] != ':') || (hwAddr[5] != ':') || (hwAddr[8] != ':') || (hwAddr[11] != ':') || (hwAddr[14] != ':') 
      )) 
    {
        assert( !"ARPPackage::setSenderHWAddress Error setting the sender MAC address!" );
        throw Exception("ARP header data: error setting the sender MAC address.");
    }

    memset( header_->arp_sha, 0, sizeof(header_->arp_sha) );
    if( !hwAddr.empty() ) {
        u8* a = &(header_->arp_sha[0]);
        sscanf( hwAddr.c_str(), "%x:%x:%x:%x:%x:%x", (i32*)(a), (i32*)(a+1), (i32*)(a+2), (i32*)(a+3), (i32*)(a+4), (i32*)(a+5) );
    }
}

inline void ARPPackage::setSenderProtoAddress( const std::string& protoAddr )
{
    check_header();

    if( !protoAddr.empty() && (
        (protoAddr.length() < strlen("0.0.0.0")) ||
        (protoAddr.length() > strlen("000.000.000.000")) 
      ))
    {
        assert( !"ARPPackage::setSenderProtoAddress Error setting the sender protocol address!" );
        throw Exception("ARP header data: error setting the sender protocol address.");
    }

    memset( header_->arp_spa, 0, sizeof(header_->arp_spa) );
    if( !protoAddr.empty() ) {
        u8* a = &(header_->arp_spa[0]);
        sscanf( protoAddr.c_str(), "%d.%d.%d.%d", (i32*)(a), (i32*)(a+1), (i32*)(a+2), (i32*)(a+3) );
    }
}

inline void ARPPackage::setTargetHWAddress( const std::string& hwAddr )
{
    check_header();

    if( !hwAddr.empty() && ( 
        (hwAddr.length() != strlen("00:00:00:00:00:00")) ||
        (hwAddr[2] != ':') || (hwAddr[5] != ':') || (hwAddr[8] != ':') || (hwAddr[11] != ':') || (hwAddr[14] != ':') 
      )) 
    {
        assert( !"ARPPackage::setTargetHWAddress Error setting the target MAC address!" );
        throw Exception("ARP header data: error setting the target MAC address.");
    }

    memset( header_->arp_tha, 0, sizeof(header_->arp_tha) );
    if( !hwAddr.empty() ) {
        u8* a = &(header_->arp_tha[0]);
        sscanf( hwAddr.c_str(), "%x:%x:%x:%x:%x:%x", (i32*)(a), (i32*)(a+1), (i32*)(a+2), (i32*)(a+3), (i32*)(a+4), (i32*)(a+5) );
    }
}

inline void ARPPackage::setTargetProtoAddress( const std::string& protoAddr )
{
    check_header();

    if( !protoAddr.empty() && (
        (protoAddr.length() < strlen("0.0.0.0")) ||
        (protoAddr.length() > strlen("000.000.000.000")) 
      ))
    {
        assert( !"ARPPackage::setTargetProtoAddress Error setting the target protocol address!" );
        throw Exception("ARP header data: error setting the target protocol address.");
    }

    memset( header_->arp_tpa, 0, sizeof(header_->arp_tpa) );
    if( !protoAddr.empty() ) {
        u8* a = &(header_->arp_tpa[0]);
        sscanf( protoAddr.c_str(), "%d.%d.%d.%d", (i32*)(a), (i32*)(a+1), (i32*)(a+2), (i32*)(a+3) );
    }
}


/*******************************************************/

/**/
#endif /* __arp_package_h__ */
