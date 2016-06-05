#ifndef __aes_package_h__
#define __aes_package_h__

#include "raw_message.h"
#include "aes_base.h"
#include <vector>

/*******************************************************/
/* 4096 cluster size * 256 max number of clusters inside chunked AES 
   + 16 bytes AES header (header 16 or 12 bytes) */
#define MAX_AESPACKAGE_SIZE         0x100010

/* offsets in AES header */
#define AES_KEY_CLUSTERID_OFFSET    40
#define AES_IV_CLUSTERID_OFFSET     24
#define AES_DATALEN_OFFSET          8
#define AES_CR_HEADER_LEN           12
#define AES_KEY_HEADER_LEN          16

class OTP_Processor;

/*******************************************************/
/*  AESPackage implementation in RawMessage inheritance */
class AESPackage : public RawMessage
{
    friend class OTP_Processor;

public:
    AESPackage();
    AESPackage( PackageType type );
    AESPackage( const AESPackage& package );

    virtual ~AESPackage();

    /*  Presend AES data package 
        Contains AES_KeyStore structure and used between AES and OTP presend operation only
        @param orderId differs from cluster_id. This is element ordering number in outgoing key queue.
               Has only positive value and replaces with cluster_id after PreSend completion.
    */
    static void makePreSend( const AES_KeyStore& keyStore, 
                             u64 orderId,
                             u64 magicQWord,
                             AESPackage* package );

    /*  Makes AES package with crypted data from RawMessage */
    static AESPackage* makeCRData( const AES_KeyStore& keyStore, 
                                   const RawMessage& message,
                                   u64 clusterId );

    /*  Makes AES package with decrypted data from AesPackage type_CRData */
    static AESPackage* makeDCData( const AES_KeyStore& keyStore, 
                                   const AESPackage& cr_package );

    inline void setData( const u8* ptr, u16 sz );

    inline u64 getId( void ) const;
    inline u32 getDataLen( void ) const;
    inline u32 getAlignedDataLen( void ) const;

    /*  Set data length and update buffer (valid for CR and DC packages only) */
    virtual void setDataLen(u32 dataLen) 
    {
        assert( (type_ & type_AES) && "AESPackage::setDataLen Invalid package type!" );

        dataLen_ = dataLen;
        if( (type_ & type_Key) == type_AES )
            *(u32*)(buffer_+8) = dataLen; 
    }

    /*  Set id and update buffer */
    virtual void setId(u64 newId) 
    {
        assert( (type_ & type_AES) && "AESPackage::setId Invalid package type!" );

        if( type_ & type_Fragment )
            assert( !"AESPackage::setId  Unable to set id for AES package (package is chunk)!"); 
        else if( (type_ & type_PreSend) == type_PreSend ) {
            id_ = newId;
            *(u64*)(buffer_+8+sizeof(AES_KeyStore)) = newId; 
        }
        else if( (type_ & type_IV) == type_IV ) {
            id_ = newId;
            *(u64*)(buffer_+8+AES_KEY_IV_LEN) = newId; 
        }
        else if( (type_ & type_Key) == type_Key ) {
            id_ = newId;
            *(u64*)(buffer_+8+AES_KEY_LEN) = newId; 
        }
        else if( type_ & type_AES ) {
            id_ = newId;
            *(u64*)(buffer_) = newId; 
        }
        else
            assert( !"AESPackage::setId Invalid AES package type!" );
    }

    virtual void setMagicQWord(u64 qword)
    { 
        assert( (type_ & type_AES) && "AESPackage::setMagicQWord Invalid package type!" );

        if( type_ & type_Fragment )
            assert( !"AESPackage::setMagicQWord Unable to set magic word for AES package (package is chunk)!"); 
        else if( (type_ & type_PreSend) == type_PreSend )
            *(u64*)(buffer_) = qword; 
        else if( (type_ & type_IV) == type_IV ) 
            *(u64*)(buffer_) = qword^16; 
        else if( (type_ & type_Key) == type_Key )
            *(u64*)(buffer_) = qword^32;
        else
            assert( !"AESPackage::setMagicQWord Unable to set magic word for AES package (not compatible)!");

        magicQWord_ = qword;
    }

protected:
    virtual void setType( void )
    { type_ |= type_AES; }
};
typedef std::vector<AESPackage> AESPackagesT;

/***********************************************************************/
inline u64 AESPackage::getId( void ) const
{
    assert( (type_ & type_AES) && "AESPackage::getId Invalid package typee!" );

    u64 id = 0;
    if( type_ & type_Fragment )
        id = id_;
    else if( (type_ & type_PreSend) == type_PreSend )
        id = (size_ > AES_KEY_HEADER_LEN) ? *(u64*)(buffer_ + 8 + sizeof(AES_KeyStore) ) : id_;
    else if( (type_ & type_IV) == type_IV )
        id = (size_ > AES_KEY_HEADER_LEN) ? *(u64*)(buffer_ + 8 + 16 ) : id_;
    else if( (type_ & type_Key) == type_Key )
        id = (size_ > AES_KEY_HEADER_LEN) ? *(u64*)(buffer_ + 8 + 32 ) : id_;
    else if( type_ & type_AES )
        id = (size_ > 8) ? *(u64*)buffer_ : id_;
    else
        assert( !"AESPackage::getId Invalid using: invalid package type!" );

    if( id )
        *const_cast<u64*>(&id_) = id;
    return id;
}

inline u32 AESPackage::getDataLen() const
{
    assert( (type_ & type_AES) && "AESPackage::getDataLen Invalid package type!" );

    u32 dataLen = 0;
    if( (type_ & type_Fragment) == type_Fragment )
        dataLen = size_ - headerLen_;
    else if( (type_ & type_Key) == type_Key )
        dataLen = (size()-AES_KEY_HEADER_LEN);
    else if( type_ & type_AES )
        dataLen = (size_ > AES_CR_HEADER_LEN) ? *(u32*)(buffer_ + 8) : dataLen_;

    if( dataLen )
        *const_cast<u32*>(&dataLen_) = dataLen;
    return dataLen;
}

inline u32 AESPackage::getAlignedDataLen() const
{
    /* refresh dataLen_ from header */
    u32 dataLen = getDataLen();
    assert( dataLen == dataLen_ && 
            "AESPackage::getAlignedDataLen Error receiveing data length from header!" );

    if( type_ & type_Fragment )
        assert( !"AESPackage::getAlignedDataLen Forbidden measure of alignment for chunked data!" );
    else if( (type_ & type_Key) == type_AES )
        return (dataLen + ((dataLen+AES_CR_HEADER_LEN)%8));
    else if( (type_ & type_Key) == type_Key )
        return dataLen;

    assert( !"AESPackage::getAlignedDataLen error!" );
    return 0;
}

inline void AESPackage::setData( const u8* ptr, u16 sz )
{ 
    assert( sz && ptr && "AESPackage::setData <null> input data!" );

    sz = sz > maxDataLen_ ? (u16)maxDataLen_ : sz;
    if( (type_ & type_Key) == type_Key )
        reserve(sz + AES_KEY_HEADER_LEN);
    else if( (type_ & type_Key) == type_AES )
        reserve(sz + AES_CR_HEADER_LEN);

    memcpy(buffer_ + headerLen_, ptr, sz);
    setDataLen( sz );
}


/*******************************************************/

/**/
#endif /* __aes_package_h__ */
