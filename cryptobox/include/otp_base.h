#ifndef __otp_base_h__
#define __otp_base_h__

#include "enque_buffer_sender.h"
#include "otp_package.h"
#include "gap_detector.h"

#include <memory>

/*  By controlling this parameters we can increase efficiency of cryptobox processing */
#define  DEF_OTP_IN_BUFFER_SIZE         5120            /* 5 Mb */
#define  DEF_OTP_OUT_BUFFER_SIZE        0               /* sync */
#define  DEF_SEQGAP_BUFFER_SIZE         10240           /* 10  Mb */
#define  DEF_OTP_IMAGE_CACHE_SIZE       102400          /* 100 Mb */
#define  DEF_OTP_IMAGE_PATH             "./imageotp"    /* image path */

#define  DEF_PAGE_DELIVERY_TIMELIMIT    80              /* [mlsec] waiting time for deliverying the page 
                                                           with a cluster what not filled completely */
#define  DEF_GAP_TIME_EXPIRATION_LIMIT  10000           /* [mlsec] expiration time after what the incoming 
                                                           cluster with required sequence number not received 
                                                           from channels */

#define  OTP_POSITIONING_FILENAME       "./otp_position"    /* positioning file */

/************************************************************************************/
class OTP_Processor : public EnqueBufferSender, 
                      public Communicator
{
    friend class AES_KeyExchange;
    friend class ChannelObserver;
public:
    /* @param direction the method ciphering or de-ciphering */
    OTP_Processor(NotificationsMgrBase* notifier);
    virtual ~OTP_Processor();

    /*  Verify and initialize filesystem objects that needed to normal OTP working. 
        @throws Exception if we have some error (CryptoBox must be closed!)
    */
    void init_otp_outgoing( void );

    /*  Read one cluster from the image
        @param decode defines which headIn or headOut should be read at one cluster
    */
    void readOtpCluster( bool decode );

    /*  Rewind image read position at the beginning 
        @param decode defines which headIn or headOut should be read at one cluster
    */
    void rewindOtp( bool decode );

    /*  Image creation service
        @param imagesize in Mb
        @throws Exception if fails
    */
    static void createImage(const std::string& path, u32 imagesize);

    /*  Obtains module statistics */
    inline void getTunnelBuffersUsage( i32* bytes, i32* limit ) const;
    inline void getOtpOutBuffersUsage( i32* bytes, i32* limit ) const;

    /*  Get encoding throughput 
        Note: measure time interval is 10 second
    */
    inline u32 getThroughput() const
    { return throughput_; }

    /*  Get magic word  (for AES_KeyExchange only) */
    inline u64 getInMagic( void ) const
    { return magicInQWord_; }

    /*  Clusters positions accessing */
    inline u64 getInClustersPosition() const
    { return imgInPos_; }

    inline u64 getOutClustersPosition() const
    { return imgOutPos_; }

    /*  Creates magic qword for outgoing connection data */
    void createOutMagicQWord( const AES_KeyStore& keyStore );

    /*  Obtains magic qword from incoming connection data (first AES key and IV) */
    void createInMagicQWord( void );

protected:
    /* EnqueBufferSender::Communicator implementation */ 

    /*  Read dublicate OTP image handle for incoming data processing 
        @note imgInPos_ should be initialized before from the incoming data queue
        @throws Exception if error
    */
    void init_otp_incoming( void );

    /*  Perform package synchronously
        @note when has failure then forces to shutting down cipherer by shutdown flag switch
        @type equals AES_Module: outgoing message what was enqueued from AES cryptor module 
        @type equals SSL_ChannelOne or Two: incoming message what was enqueued from SSL channels 
        @returns number of processed bytes, this number used to queue clearing
    */
    virtual u32 do_perform(const RawMessage& msg, SenderType type);

    virtual SenderType get_type( void )
    { return Communicator::OTP_Module; }

    /*  Encode package. Returns bytes of encoded data. */
    u32 processEncode( const AESPackage& package );

    /*  Decode package. Returns bytes of decoded data. */
    u32 processDecode( const Cluster& cluster );

    /*  Extacts from cluster the first well-formed AES packages while don't meet the fragmented packages
        in AES chain.
        Normally chunked AES package may be first or last in chain or be contained as entire cluster.
        @throws Exception if clusters data integrity was compromised
    */
    void extractWellformedAES( AESPackagesT& outAESPackages );

    /*  Pushes cluster to incoming/outgoing queues. 
        When cluster number is equal to cluster number of previous element in queue then 
        it be merged to one cluster 
    */
    u32 pushOutgoing( const Cluster& cluster );
    void pushIncoming( const Cluster& cluster );

    inline void interlockedInc64( u64 volatile* ptrVal ) const;
    inline void interlockedSet64( u64 volatile* val, u64 newVal ) const;

    /*  Calculate encoding throughput 
        Note: measure time interval is 10 second
    */
    static inline void calcEncodeThroughput( u32 processed, u32 volatile* throughput );

protected:
    /*  Casts RawMessage to AESPackage object without copying with AES header checking  */
    inline static const AESPackage* castToAes( const RawMessage& message );

    /*  Casts RawMessage to OTP Cluster object without copying with OTP header checking  */
    inline const Cluster* castToOtp( const RawMessage& message );

    /*  limitations for sequences Id validation */
    inline Marker64T sequenceId_current_limits( void ) const;

private:
    /*  lock for OTP data read operations */
    mutable Mutex otpLockIn_;
    mutable Mutex otpLockOut_;

    /*  lock for incoming/outogoing queues operations */
    Mutex inQLock_;
    Mutex outQLock_;

    GapDetector gapDetector_;

    ClustersStockT incomingQ_;
    ClustersStockT outgoingQ_;

    Cluster headIn_;
    Cluster headOut_;

    std::auto_ptr<File> image_;
    std::auto_ptr<File> imageDub_;

    u16 headInPosition_;
    u16 headOutPosition_;

    /*  positions in cluster numbers    */
    volatile u64 imgInPos_;
    volatile u64 imgOutPos_;

    /*  must equals after connection */
    u64 magicInQWord_;

    /*  throughput calculation member */
    volatile u32 throughput_;

    /*  image size in cluster numbers    */
    u64 image_size_;

    /*  number of rewinds during the session */
    i32 in_rewind_counter_;
    i32 out_rewind_counter_;
};

inline Marker64T OTP_Processor::sequenceId_current_limits() const
{
    static u64 firstClusterId = 0;
    Marker64T mark;

    mark.second = Cluster::makeClusterIdFromNum( imgInPos_ < imgOutPos_ ? imgOutPos_ : imgInPos_ );
    /* 32 clusters as fora (2 socket buffer) */
    mark.second += 0x1000;

    /* low limitation */
    if( firstClusterId == 0 )
        firstClusterId = Cluster::makeClusterIdFromNum( imgInPos_ ? imgInPos_ : 0 );

    mark.first = firstClusterId;
    return mark;
}

inline const AESPackage* OTP_Processor::castToAes( const RawMessage& message )
{
    /*  validate input data */
    if( (message.get() == NULL) || (message.size() == 0) ) {
        assert( !"OTP_Processor::castToAes <null> input data!");
        throw Exception("AES type cast: <null> input data");
    }

    AESPackage* package = static_cast<AESPackage*>( const_cast<RawMessage*>(&message) );

    /*  validate min size */
    u32 sz = package->size();
    if( sz <= AES_CR_HEADER_LEN ) {
        assert( !"OTP_Processor::castToAes Invalid unaligned length of input data!");
        throw Exception("AES type cast: invalid unaligned length of input data");
    }

    /*  validate max size */
    if( ( package->size() > MAX_AESPACKAGE_SIZE ) || ( package->size() == 0 ) ) {
        assert( !"OTP_Processor::castToAes Invalid data length of input data!");
        throw Exception("AES type cast: invalid data length of input data");
    }

    /*  validate types */
    PackageType t = package->getType();
    if( (t & type_Key) == type_Key ) /* types type_Key, type_IV, type_PreSend */
    { 
        package->headerLen_ = 8;
        if( sz != package->getDataLen() + AES_KEY_HEADER_LEN ) {
            assert( !"OTP_Processor::castToAes Error reading data length from AES/IV key header!" );
            throw Exception("AES type cast: error reading data length from AES/IV key header");
        }
    }
    else if( t & type_AES ) /* types type_DCData, type_CRData */
    {   
        package->headerLen_ = AES_CR_HEADER_LEN;
        if( sz != package->getAlignedDataLen() + AES_CR_HEADER_LEN && 
            sz != package->getDataLen() + AES_CR_HEADER_LEN ) 
        {
            assert( !"OTP_Processor::castToAes Error reading data length from DC/CR data header!" );
            throw Exception("AES type cast: error reading data length from DC/CR data header");
        }
    }
    else 
    {
        assert( !"OTP_Processor::castToAes Invalid type value of input data!");
        throw Exception("AES type cast: invalid type value of input data");
    }

    /* refresh id */    
    package->getId();
    return package;
}

inline const Cluster* OTP_Processor::castToOtp( const RawMessage& message )
{
    /*  validate input data */
    if( (message.get() == NULL) || (message.size() == 0) ) {
        assert( !"OTP_Processor::castToOtp <null> input data!");
        throw Exception("OTP type cast: <null> input data");
    }

    Cluster* cluster = static_cast<Cluster*>( const_cast<RawMessage*>(&message) );

    /*  validate min size */
    u32 sz = cluster->size();
    if( sz <= OTP_HEADER_LEN ) {
        assert( !"OTP_Processor::castToOtp Invalid unaligned length of input data!");
        throw Exception("OTP type cast: invalid unaligned length of input data");
    }

    /*  validate max size */
    if( ( cluster->size() > MAX_OTPCLUSTER_SIZE ) || ( cluster->size() == 0 ) ) {
        assert( !"OTP_Processor::castToOtp Invalid data length of input data!");
        throw Exception("OTP type cast: invalid data length of input data");
    }

    /*  validate type */
    PackageType t = cluster->getType();
    if( t & type_OTP ) {
        cluster->headerLen_ = OTP_HEADER_LEN;
        if( sz != cluster->getDataLen() + OTP_HEADER_LEN ) {
            assert( !"OTP_Processor::castToOtp Error reading data length from cluster header!" );
            throw Exception("OTP type cast: error reading data length from cluster  header");
        }
    }
    else {
        assert( !"OTP_Processor::castToOtp Invalid type value of input data!");
        throw Exception("OTP type cast: invalid type value of input data");
    }

    /* refresh sequence id */
    cluster->getId();

    /* refresh  type */
    if( Cluster::InvalidChunk != cluster->getChunkId() )
        cluster->setChunked(true);

    /* validate sequence id */
    /*Marker64T limits = sequenceId_current_limits();
    if( seqId < limits.first  || seqId > limits.second ) {
        assert( !"OTP_Processor::castToOtp Invalid sequence number of cluster!");
        throw Exception("AES type cast: invalid sequence number of cluster");
    }*/
    return cluster;
}

extern u32 GV_OtpInBufferSize;
extern u32 GV_OtpOutBufferSize;

inline void OTP_Processor::getTunnelBuffersUsage( i32* bytes, i32* limit ) const {
    *bytes = getInBufferUsage();
    *limit = (GV_OtpInBufferSize << 10);
}

inline void OTP_Processor::getOtpOutBuffersUsage( i32* bytes, i32* limit ) const {
    *bytes = getOutBufferUsage();
    *limit = (GV_OtpOutBufferSize << 10);
}

inline void OTP_Processor::interlockedInc64( u64 volatile* ptrVal ) const 
{
#ifdef WIN32
    InterlockedIncrement( (long volatile*)ptrVal );
#else
    ++(*ptrVal);
#endif
}

inline void OTP_Processor::interlockedSet64( u64 volatile* ptrVal, u64 newVal ) const 
{
#ifdef WIN32
    InterlockedExchange( (long volatile*)ptrVal, static_cast<long>(newVal) );
#else
    (*ptrVal) = newVal;
#endif
}

/**/
#endif /* __otp_base_h__ */
