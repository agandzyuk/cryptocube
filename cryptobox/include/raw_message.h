#ifndef __raw_message_h__
#define __raw_message_h__

#include "message.h"
#include "connection.h"

/***********************************************************/
#define MAX_RAWPACKAGE_SIZE     0x100000     /* 1Mb */

/****************************************/
/*   PackageType enumeration            */
/****************************************/
/*  00000000    // inv                  */
/*  00000001    // cr                   */
/*  00000010    // chunked              */
/*  00000100    // aes                  */
/*  00000101    // aes encrypted        */
/*  00001000    // otp                  */
/*  00001001    // otp encrypted        */
/*  00010000    // ip                   */
/*  00100100    // aes key              */
/*  01100100    // aes key iv           */
/*  10100100    // pre-send             */
/****************************************/
enum PackageType 
{
    type_Invalid    = 0,
    type_CR         = 1,        /* encrypted package */
    type_Fragment   = 2,        /* chunked package */
    type_AES        = 4,        /* AES package */
    type_DCData     = type_AES, /* AES decrypted package */
    type_CRData     = 5,        /* AES encrypted package */
    type_OTP        = 8,        /* OTP cluster */
    type_CRCluster  = 9,        /* OTP encrypted cluster */
    type_Eth        = 16,       /* Ethernet package */
    type_IP         = 24,       /* IP package */
    type_Key        = 36,       /* AES key package */
    type_ARP        = 40,       /* ARP package */
    type_IPv6       = 56,       /* IPv6 package */
    type_IV         = 100,      /* AES key IV package */
    type_PreSend    = 164,      /* Pre-send AES package */
    type_RAW        = 255,      /* RAW package */
};


/**************************************************************************/
/*  Abstraction for support of typecasts between successors */
class RawMessage : public Message
{
public:
    RawMessage();
    RawMessage(u32 reserveSize);
    RawMessage(const RawMessage& message);
    RawMessage(const u8* srcBuf, u32 bufSize);

    /*  Casts Message to RawMessage object without copying */
    inline static RawMessage* castToRaw( const u8* pBuffer, u32 bufferSize );
    inline static RawMessage* castToRaw( const Message& message );

    inline RawMessage& operator=( const RawMessage& message );

    inline u8   getVersion( void ) const;
    inline PackageType getType() const;
    inline u64  getId( void ) const;
    inline u32  getDataLen( void ) const;
    inline u64  getMagicQWord( void ) const;
    inline u8   getHeaderLen( void ) const;

    inline bool isEncoded( void ) const;
    inline bool isChunked( void ) const;

    inline void setEncoded( bool encoded );

    /*  gets data without header */
    inline const u8* getData( void ) const;
    inline u8* getData( void );

    /*  copy data without header 
        @throws Exception if error
    */
    inline void setData(const u8* buffer, u16 len);

    /*  copy data without header 
        @throws Exception if error
    */
    virtual void setDataLen(u32)
    { assert(!"RawMessage setDataLen(u32) should not be used!"); }

    /*  add data without header 
        @returns number of bytes what added to message
    */
    inline u16 addData(const u8* ptr, u16 sz);

    /* implementations in Cluster, IPPackage and AESPackage */
    virtual void setId(u64)
    { assert(!"RawMessage setId(u64) should not be used!"); }

    virtual void setMagicQWord(u64)
    { assert(!"RawMessage setMagicQWord(u64) should not be used!"); }

protected:
    virtual void setType( void ) 
    { assert( !"RawMessage setType() Using RawMessage object without successors instantiation!" ); type_ = type_Invalid; }

    virtual void setChunked( bool enable ) {
        if( type_ == type_Invalid )
            setType();
        if( enable )
            type_ |= type_Fragment;
        else
            type_ &= ~type_Fragment;
    }

protected:
    u8   version_;
    u8   type_;
    u64  id_;
    u8   headerLen_;
    u32  dataLen_;
    u32  maxDataLen_;
    u64  magicQWord_; /* reserved for down typecast */
    u8   sendMethod_;

    MarkersT aesMarkers_;
};
typedef std::vector<RawMessage> RawMessagesT;
typedef std::queue<RawMessage>  RawMessagesQueueT;

/**************************************************************************/
inline RawMessage* RawMessage::castToRaw( const Message& message )
{
    return castToRaw( message.get(), message.size() );
}

inline RawMessage* RawMessage::castToRaw( const u8* pBuffer, u32 bufferSize )
{
    if( (pBuffer == NULL) || (bufferSize == 0) )
        throw SplitRawBufferToMessagesBase::ZeroMsgReceivedException("Raw message");

    RawMessage* raw = new RawMessage();
    raw->set_protected_using(bufferSize);
    raw->buffer_ = const_cast<u8*>(pBuffer);
    return raw;
}

inline RawMessage& RawMessage::operator=( const RawMessage& message )
{
    *(Message*)this = message;
    version_    = message.version_;
    type_       = message.type_;
    headerLen_  = message.headerLen_;
    maxDataLen_ = message.maxDataLen_;

    id_         = message.id_;
    dataLen_    = message.dataLen_;
    magicQWord_ = message.magicQWord_;
    sendMethod_ = message.sendMethod_;
    aesMarkers_ = message.aesMarkers_;

    return *this;
}

inline u8 RawMessage::getVersion() const { 
    return version_; 
}

inline PackageType RawMessage::getType() const { 
    return (PackageType)type_; 
}

inline u64 RawMessage::getId() const {
    return id_; 
}

inline u32 RawMessage::getDataLen() const { 
    return dataLen_; 
}

inline u64 RawMessage::getMagicQWord( void ) const { 
    return magicQWord_; 
}

inline const u8* RawMessage::getData() const { 
    return (buffer_ == NULL ? NULL : buffer_ + headerLen_); 
}

inline u8* RawMessage::getData() { 
    return (buffer_ == NULL ? NULL : buffer_ + headerLen_); 
}

inline u8 RawMessage::getHeaderLen() const { 
    return headerLen_; 
}

inline bool RawMessage::isChunked( void ) const {
    return (type_ & (u8)type_Fragment) == type_Fragment;
}

inline bool RawMessage::isEncoded() const { 
    return (type_ & type_CR) == type_CR;
}

inline void RawMessage::setEncoded( bool encoded ) { 
    if( type_ == type_Invalid )
        setType();
    if( encoded )
        type_ |= (u8)type_CR;
    else
        type_ &= ~(u8)type_CR;
}

inline void RawMessage::setData( const u8* ptr, u16 sz )
{ 
    assert( sz && ptr && "RawMessage::setData <null> input data!" );

    sz = sz > maxDataLen_ ? (u16)maxDataLen_ : sz;
    set_protected_using(0);
    reserve(sz + headerLen_);
    memcpy(buffer_ + headerLen_, ptr, sz);
    setDataLen( sz );
}

inline u16 RawMessage::addData(const u8* ptr, u16 sz) 
{
    assert( sz && ptr && "RawMessage::addData <null> input data!");

    sz = (u16)(sz + dataLen_ > maxDataLen_ ? maxDataLen_ - dataLen_ : sz);
    Message::add(ptr, sz);
    setDataLen( dataLen_ + sz );
    return sz;
}

/**************************************************************************/
/*  Splitter will be used when several IP packages in the one recv buffer */
class RawSplitter : public SplitRawBufferToMessagesBase
{
friend class RawMessage;
public:
    RawSplitter(u16 splitBy, bool onSend);
    virtual ~RawSplitter();

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
    u16  splitBy_;
    bool onSend_;
};

/*******************************************************/

/**/
#endif /* __raw_message_h__ */
