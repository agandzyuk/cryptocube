#ifndef __ip6_package_h__
#define __ip6_package_h__

#include "raw_message.h"

#ifndef WIN32
    #include <netinet/ip.h>
    #include <arpa/inet.h>
#else
   #include <in6addr.h>

   #ifndef IPPROTO_IPV6
       #define IPPROTO_IPV6     41
   #endif
   #ifndef IPPROTO_ROUTING
       #define IPPROTO_ROUTING  43
   #endif
   #ifndef IPPROTO_FRAGMENT
       #define IPPROTO_FRAGMENT 44
   #endif
   #ifndef IPPROTO_ESP
       #define IPPROTO_ESP      50
   #endif
   #ifndef IPPROTO_AH
       #define IPPROTO_AH       51
   #endif
   #ifndef IPPROTO_ICMPV6
       #define IPPROTO_ICMPV6   58
   #endif
   #ifndef IPPROTO_NONE
       #define IPPROTO_NONE     59
   #endif
   #ifndef IPPROTO_DSTOPTS
       #define IPPROTO_DSTOPTS  60
   #endif
   #ifndef IPPROTO_HOPOPTS
       #define IPPROTO_HOPOPTS  0
   #endif
#endif


/*******************************************************/
struct ip6_header {
    u32 flow_lbl;
    u16 payload_len;
    u8  next_header_type;
    u8  hop_limit;
    struct in6_addr source_address;
    struct in6_addr dest_address;
};

/*******************************************************/
/*  IPPackage implementation in RawMessage inheritance */
class IP6Package : public RawMessage
{
public:

    IP6Package( const RawMessage& ip6Package );
    virtual ~IP6Package();

    /*  Casts Message to IP6Package object without copying with IP header checking  */
    static IP6Package* castToIP6( const u8* pBuffer, u32 bufferSize );
    static inline IP6Package* castToIP6( const Message& message );

    inline IP6Package& operator =(const IP6Package& right);
    inline u8  getPriority( void ) const;
    inline u32 getFlowID( void ) const;
    inline u16 getPayloadLen( void ) const;
    inline u8  getNextHeaderType( void ) const;
    inline u8  getHopLimit( void ) const;
    inline std::string getSrcAddress( void ) const;
    inline std::string getDestAddress( void ) const;
    inline const u8* getSrcIP6( void ) const;
    inline const u8* getDestIP6( void ) const;

    /*  package creation */
    inline void setData( const u8* buffer, u16 len );
    inline void setPriority( u8 priority );
    inline void setFlowID( u32 id );
    inline void setNextHeaderType( u8 next_hdr_type );
    inline void setHopLimit( u8 hop_limit );
    inline void setSrcAddress( const std::string& srcIP );
    inline void setDestAddress( const std::string& destIP );

    virtual void setDataLen(u32)
    { assert(!"IP6Package setDataLen Should not used!"); }

    virtual void setId(u64)
    { assert(!"IP6Package setId Should not used!"); }

    virtual void setMagicQWord(u64)
    { assert(!"IP6Package setMagicQWord Should not be used!"); }

protected:
    IP6Package();

    virtual void setType( void )
    { type_ = type_IPv6; }

    inline void check_header( void ) {
        if( NULL == header_ ) {
            header_ = (struct ip6_header*)buffer_;
            headerLen_ = sizeof(struct ip6_header);
        }
    }

    struct ip6_header* header_;
};
typedef std::vector<IP6Package> IP6PackagesT;

/**********************************************************************/
inline IP6Package* IP6Package::castToIP6( const Message& message ) 
{
    return castToIP6( message.get(), message.size() );
}

inline IP6Package& IP6Package::operator =(const IP6Package& right)
{
    *static_cast<RawMessage*>(this) = right;
    header_ = (struct ip6_header*)buffer_;
    return *this;
}

inline u8 IP6Package::getPriority() const
{ return (header_->flow_lbl & 0x0000000F); }

inline u32 IP6Package::getFlowID() const
{
    u32 flow_lbl = ntohl( header_->flow_lbl );
    return (flow_lbl & 0x00FFFFFF);
}

inline u16 IP6Package::getPayloadLen() const
{ return ntohs(header_->payload_len); }

inline u8 IP6Package::getNextHeaderType() const
{ return header_->next_header_type; }

inline u8 IP6Package::getHopLimit() const
{ return header_->hop_limit; }

inline std::string IP6Package::getSrcAddress() const
{
#ifndef WIN32
    s8 buf[INET6_ADDRSTRLEN];
    const s8* ret = NULL;
    if( NULL == (ret = inet_ntop(AF_INET6, &(header_->source_address), buf, INET6_ADDRSTRLEN )) )
        return std::string("00:00:00:00:00:00");
    return ret;
#else
    assert( !"IP6Package::getSrcAddress Can't using under WIN32 platform OS!" );
    return std::string("00:00:00:00:00:00");
#endif
}

inline std::string IP6Package::getDestAddress() const
{
#ifndef WIN32
    s8 buf[INET6_ADDRSTRLEN];
    const s8* ret = NULL;
    if( NULL == (ret = inet_ntop(AF_INET6, &(header_->dest_address), buf, INET6_ADDRSTRLEN )) )
        return std::string("00:00:00:00:00:00");
    return ret;
#else
    assert( !"IP6Package::getDestAddress Can't using under WIN32 platform OS!" );
    return std::string("00:00:00:00:00:00");
#endif
}

inline const u8* IP6Package::getSrcIP6( void ) const
{
    return header_->source_address.s6_addr;
}

inline const u8* IP6Package::getDestIP6( void ) const
{
    return header_->dest_address.s6_addr;
}

inline void IP6Package::setData( const u8* buffer, u16 len )
{
    set_protected_using(0);
    headerLen_ = sizeof(struct ip6_header);
    reserve( len + headerLen_ );
    header_ = (struct ip6_header*)buffer_;
    memcpy( buffer_+headerLen_, buffer, len );
    dataLen_ = len;
    header_->payload_len = htons( len );
}

inline void IP6Package::setPriority( u8 priority )
{
    check_header();
    header_->flow_lbl &= 0xFFFFFFF0;
    header_->flow_lbl |= priority;
}

inline void IP6Package::setFlowID( u32 id )
{ 
    check_header();
    u32 flow_id = htonl( id ) << 8;
    header_->flow_lbl &= 0xFF;
    header_->flow_lbl |= flow_id;
}

inline void IP6Package::setNextHeaderType( u8 next_hdr_type )
{
    check_header();
    header_->next_header_type = next_hdr_type;
}

inline void IP6Package::setHopLimit( u8 hop_limit )
{
    check_header();
    header_->hop_limit = hop_limit;
}

inline void IP6Package::setSrcAddress( const std::string& srcIP )
{
    check_header();
#ifndef WIN32
    inet_pton(AF_INET6, srcIP.c_str(), &(header_->source_address));
#else
    assert( !"IP6Package::setSrcAddress Can't using under WIN32 platform OS!" );
#endif
}

inline void IP6Package::setDestAddress( const std::string& destIP )
{
    check_header();
#ifndef WIN32
    inet_pton(AF_INET6, destIP.c_str(), &(header_->dest_address));
#else
    assert( !"IP6Package::setDestAddress Can't using under WIN32 platform OS!" );
#endif
}


/**/
#endif /* __ip6_package_h__ */
