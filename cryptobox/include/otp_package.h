#ifndef __otp_package_h__
#define __otp_package_h__

#include "aes_package.h"
#include "connection.h"

#include <map>

/*******************************************************/
#define UNASSIGNED_CLUSTER_ID       0
#define INVALID_CLUSTER_LENGTH      0
#define FIRST_ASSIGNED_CLUSTER_ID   0x8000000000000000  /* negative 64-bit half start */

#define MAX_OTPCLUSTER_SIZE         0x100E              /* 4110 bytes */ 
                                                        /* -----------------*/
#define CLUSTER_DATALEN             0x1000              /* 4096 bytes */
                                                        /* 8 bytes: cluster id */ 
#define OTP_CHUNKID_OFFSET          8                   /* 2 bytes: chunkId */
#define OTP_USEDLEN_OFFSET          10                  /* 4 bytes: used bytes */
                                                        /* -----------------*/
#define OTP_HEADER_LEN              14                  /* 14 bytes: header */

class OTP_Processor;

/*******************************************************/
/*  Cluster implementation of RawMessage inheritance */
class Cluster : public RawMessage
{
    friend class OTP_Processor;

public:
    enum SendMethod {
        Undefined   = 0,
        ChannelOne  = 1,
        ChannelTwo  = 2,
        Random      = 3,
        Different   = 4,
    };

    enum ChunkMaskInfo {
        NoChunk         = 0,
        BegOfChain      = 0x2000,
        EndOfChain      = 0x4000,
        EndOfCluster    = 0x8000,
        InvalidChunk    = 0xFFFF,
    };

public:
    Cluster();
    Cluster(const Cluster& message);
    virtual ~Cluster();

    static std::vector<Cluster> fromRawAes( const RawMessage& msg, u16 offset_head_data_begin );
    static std::vector<Cluster> fromRawOtp( const RawMessage& msg );

    /*  Encode data in cluster. */
    void encode( const Cluster& otp_head, u16 offset_head_data_begin );

    /*  Decode data in cluster.
        @param: magicQWord is required parameter, because we must remember the positions of key packages 
        immediately during data decoding. 
        It lets don't repeat parsing once again to be known about AES keys or IV positions in the cluster data.
        @param: sequenceIdLimits is required parameter what helps to select CRData regions in the cluster data. 
    */
    void decode( const Cluster& otp_head, 
                 u16 offset_head_data_begin, 
                 const u64& magicQWord,
                 const Marker64T& sequenceIdLimits );

    /*  Adds data chunk from input Cluster object
        @note Chunked type can be in several cases:
        1) the first AES package in chain is the chunk 
        2) the entire cluster data is the chunk of one AES package
        @note cluster which must be extended and added are should be already decoded.
        use extractWellformedAES after addCluster operation to validation that chunks 
        are collected to well-formed AES package
        @note max size of chunked cluster is limited by MAX_AESPACKAGE_SIZE because used only 
        in transactions between OTP processor and AES exchange
        @throws Exception if clusters data integrity was compromised
    */
    void addCluster( const Cluster& cluster );

    /*  @param clusterId the cluster unique identifier that used for sequences numbering
        and validation in the transaction via network
        @returns cluster number from clusterId
        @note: max number of clusters is limited by 56-bit value in 64-identifier
        bit 0-7: position of network cluster in OTP image cluster 
                (128 max possible numbers of network clusters with data usage min 32 bytes)
        bit 8-62: number of OTP image cluster to which network cluster belongs
        bit 63: used in AES packages and OTP clusters storages to identify storage key value
                value 1 (negative) specify what value is the network cluster identifier
                value 0 (positive for outgoing) specify what value is key identifier of AES key/IV package in
                pre-processed OTP state (pre-send operation),
                value 0 (positive for incoming) specify what value is key identifier of AES key/IV package 
                that should be applied in AES cryptography for data decoding
    */
    inline static u64 makeClusterNumFromId( u64 clusterId );

    /*  @param cluster_num the ordering number of cluster in the OTP image
        @returns clusterId from cluster number
    */
    inline static u64 makeClusterIdFromNum( u64 cluster_num );

    /*  mem copying */
    inline void set(const u8* ptr, u16 sz);

    /*  set cluster state EndOfCluster
        @note EndOfCluster means what cluster is filled completely, 
        and getDataLen() returns size < CLUSTER_DATALEN
    */
    inline void setEndOfCluster( void ) const;

    /*  return cluster state 
        @throws exception if corrupted 
    */
    inline bool isEndOfCluster( void ) const;

    /*  reset chunkId to NoChunk state */
    inline void resetChunkState( void );

    /*  set chunk id in header */
    inline void setChunkId(u16 chunkId, bool endOfChunk);

    /*  return chunk state 
        @throws exception if corrupted 
    */
    inline bool isStartChunk( void ) const;
    inline bool isFinishChunk( void ) const;

    /*  get chunk id from header 
        @retuns: 1-byte value used for chunk id and length validation from the raw message
    */
    inline u16 getChunkId() const;

    /*  defines sending channel number for sending outgoing clusters,
        or channel from there incoming cluster was received 
        */
    inline void set_send_method( SendMethod method );

    inline u64 getId( void ) const;
    inline u32 getDataLen( void ) const;
    inline SendMethod get_send_method( void ) const;
    inline const MarkersT& get_markers( void ) const;

    virtual void setDataLen(u32 dataLen) 
    {
        assert( (size_ >= headerLen_) && 
                "Cluster::setDataLen Reserve cluster's buffer on first!" );
        assert( (dataLen <= maxDataLen_) && 
                "Cluster::setDataLen Invalid length to set (greater than OTP cluster size)!" );
        dataLen_ = dataLen;
        *(u32*)(buffer_ + OTP_USEDLEN_OFFSET) = dataLen;
    }

    virtual void setId(u64 new_Id) { 
        *(u64*)buffer_ = new_Id;
        id_ = new_Id; 
    }

    virtual void setMagicQWord(u64) {
        assert( !"Cluster::setMagicQWord should not be used!" ); 
    }

protected:
    virtual void setType( void ) { 
        type_ |= type_OTP; 
    }

private:
    /*  check header chunkId field 
        @returns false if not valid
    */
    inline bool validateChunkFieldInHeader( u16* chunkId ) const;

    /*  header: 64-bit cluster Id (id_), 
                32-bit data length (of 16-bit representation for cluster validation in utter data)
    */
};
typedef std::vector<Cluster> ClustersT;
typedef std::map<u64, Cluster> ClustersStockT;

/**********************************************************************/
inline void Cluster::set(const u8* ptr, u16 sz) 
{
    assert( sz && ptr && "Cluster::set <null> input data!");
    assert( (size_ >= headerLen_) && 
            "Cluster::set Reserve cluster's buffer on first!" );
    assert( (dataLen_ <= MAX_OTPCLUSTER_SIZE) && 
            "Cluster::set Invalid length to set (greater than OTP cluster size with header)!" );
   
    u32 check_used = *(const u32*)(ptr + OTP_USEDLEN_OFFSET);
    if( check_used > maxDataLen_ ) {
        assert( !"Cluster::set Invalid cluster data to set (data length greater than OTP cluster size)!" );
        throw Exception("OTP data: invalid cluster data to set (data length greater than OTP cluster size)");
    }

    Message::set(ptr, sz);
    u16 checkId;
    if( !validateChunkFieldInHeader( &checkId ) ) {
        assert( !"Cluster::set Invalid cluster data to set (invalid chunkId value in header)!" );
        throw Exception("OTP data: invalid cluster data to set (invalid chunkId value in header)");
    }

    id_      = *(const u64*)buffer_;
    dataLen_ = (*(const u32*)(buffer_ + OTP_USEDLEN_OFFSET));
    type_    = type_OTP;
    if( checkId && (checkId != InvalidChunk) && (checkId & (BegOfChain | EndOfChain)) )
        type_ |= type_Fragment;
}

inline u64 Cluster::makeClusterIdFromNum( u64 cluster_num ) {
    /* first 7 bit - order number in one cluster */
    return (u64)FIRST_ASSIGNED_CLUSTER_ID | (cluster_num<<7);
}

inline u64 Cluster::makeClusterNumFromId( u64 clusterId ) {
    return ((u64)FIRST_ASSIGNED_CLUSTER_ID ^ clusterId)/0x80;
}

inline void Cluster::set_send_method( SendMethod method ) {
    sendMethod_ = method;
}

inline u64 Cluster::getId() const 
{
    assert( (size_ > 8) && "Cluster::getId() Invalid request on empty package!" );
    if( id_ == UNASSIGNED_CLUSTER_ID )
        *const_cast<u64*>(&id_) = *(u64*)buffer_;
    return id_;
}

inline bool Cluster::validateChunkFieldInHeader( u16* chunkId ) const
{
    *chunkId = InvalidChunk;
    u16 checkId = *(u16*)(buffer_ + OTP_CHUNKID_OFFSET) & (~EndOfCluster);
    if( checkId == 0 )
        return true;
    if( (checkId < BegOfChain) || ((checkId & ~(BegOfChain|EndOfChain)) > 0x200) ) 
        return false;
    *chunkId = checkId;
    return true;
}

inline void Cluster::setChunkId(u16 chunkId, bool endOfChunk)
{
    assert( (chunkId < 0x201) && "Cluster::setChunkId Invalid chunkID value (exceed max 256)!" );
    assert( (size_ > OTP_HEADER_LEN) && "Cluster::setChunkId Object not initialized!" );

    if( *(u16*)(buffer_ + OTP_CHUNKID_OFFSET) & EndOfCluster ) 
        chunkId |= EndOfCluster;

    chunkId |= (endOfChunk ? EndOfChain : BegOfChain);

    *(u16*)(buffer_ + OTP_CHUNKID_OFFSET) = chunkId;
    setChunked( true );
}

inline void Cluster::resetChunkState()
{
    assert( (size_ > OTP_HEADER_LEN) && "Cluster::resetChunkState Object not initialized!" );
    *(u16*)(buffer_ + OTP_CHUNKID_OFFSET) = 
        (*(u16*)(buffer_ + OTP_CHUNKID_OFFSET) & EndOfCluster ? EndOfCluster : NoChunk);
    setChunked( false );
}

inline u16 Cluster::getChunkId() const
{
    u16 chunkId;
    if( !validateChunkFieldInHeader( &chunkId ) || (chunkId == InvalidChunk) )
        return chunkId;
    
    return (chunkId & ~(BegOfChain | EndOfChain));
}

inline bool Cluster::isStartChunk() const 
{
    u16 chunkId;
    if( !validateChunkFieldInHeader( &chunkId ) ) {
        assert( !"Cluster::isBeginOfChunk Cluster is corrupted!" );
        throw Exception("OTP data: Cluster is corrupted (invalid begin chunk Id)!");
    }
    return ((chunkId ^ BegOfChain) == 0);
}

inline bool Cluster::isFinishChunk() const 
{
    u16 chunkId;
    if( !validateChunkFieldInHeader( &chunkId ) ) {
        assert( !"Cluster::isEndOfChunk Cluster is corrupted!" );
        throw Exception("OTP data: Cluster is corrupted (invalid end chunk Id)!");
    }
    return (chunkId & EndOfChain) == EndOfChain ;
}

inline void Cluster::setEndOfCluster() const
{
    assert( (size_ > OTP_HEADER_LEN) && "Cluster::setEndOfCluster Object not initialized!" );
    *(u16*)(buffer_ + OTP_CHUNKID_OFFSET) |= EndOfCluster;
}

inline bool Cluster::isEndOfCluster() const
{
    assert( (size_ > OTP_HEADER_LEN) && "Cluster::setEndOfCluster Object not initialized!" );
    return (*(u16*)(buffer_ + OTP_CHUNKID_OFFSET) & EndOfCluster) != 0;
}

inline u32 Cluster::getDataLen() const 
{
    if( dataLen_ == INVALID_CLUSTER_LENGTH ) 
        *const_cast<u32*>(&dataLen_) = (size_ > OTP_HEADER_LEN) ? *(u32*)(buffer_ + OTP_USEDLEN_OFFSET) : 0;
    /* check length */
    if( dataLen_ > maxDataLen_ ) {
        *const_cast<u32*>(&dataLen_) = INVALID_CLUSTER_LENGTH;
        return INVALID_CLUSTER_LENGTH;
    }
    return dataLen_;
}

inline Cluster::SendMethod Cluster::get_send_method() const {
    return (Cluster::SendMethod)sendMethod_;
}

inline const MarkersT& Cluster::get_markers( void ) const {
    return aesMarkers_;
}

/*******************************************************/

/**/
#endif /* __otp_package_h__ */
