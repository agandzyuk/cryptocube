#ifndef __aes_key_exchange_h__ 
#define __aes_key_exchange_h__ 

#include "aes_base.h"
#include "aes_package.h"
#include "enque_buffer_sender.h"
#include "eventp.h"

#include <map>
#include <memory>

/**********************************************************/
#define  DEF_AESCRYPTO_IN_BUFFER_SIZE       5120        /* 5 Mb */
#define  DEF_AESCRYPTO_OUT_BUFFER_SIZE      5120        /* 5 Mb */
#define  DEF_AESCRYPTO_BACKLOG_KEY_LIMIT    10240       /* 10 Mb */

#define  DEF_AESCRYPTO_IN_KEYSTORAGE_SIZE   2048        /* 2 Mb */
#define  DEF_AESCRYPTO_OUT_KEYSTORAGE_SIZE  1024        /* 1 Mb */

#define  DEF_AESCRYPTO_PRESEND_KEY_NUMBER   512  /* 512 keys is the first pre-send to Crypto2 (common size aligned by clusters size) */
#define  DEF_AESCRYPTO_FIRSTKEY_PASSWORD    "CryptoBox.v1.0.0"

/*******************************************************/
/*  First: positive i64 value - order, negative i64 value - cluster, second - key structure */
typedef std::map<u64,AES_KeyStore> KeyStoresT;

/*******************************************************/
class KeyQueue : public KeyStoresT
{
public:
    KeyQueue( const std::string& backlogName );

    /*  keepNum_ can be changed during session relative to traffic on both sides,
        hence we should free or reserve memory inside container implementation  */
    inline void set_new_keepsize( u32 Kb );

    /*  Use to check the number of free cells in queue */
    inline u32 is_have_free( void ) const;

    /*  Current size of queue in number of key elements */
    inline u32 size( void ) const;

    /*  Current size of queue in bytes */
    inline u32 sizeInBytes( void ) const;

    /*  Clear queue */
    inline void clear_all( void );

    /*  Ovveriding from std::vector */
    inline KeyStoresT::iterator begin();
    inline KeyStoresT::iterator end();

    /*  Retreive a key and set new read position
        @param preSend true if we want reserve some amount of keys and send it to Crypto2 
        before cryptogram making
        @param pId 64-bit integer order identifier for presend or cluster_id for data encryption, 
        used later for assigning the key to OTP image cluster
    */
    AES_KeyStore* give_me_next_outgoing(bool preSend, u64* pId);

    /*  push a key */
    void push_new( const AES_KeyStore& keyStore );

    /*  Assign cluster number to key in the queue
        @param cluster_num number of OTP cluster what has the key 
        @param orderId order number of the key in queue
        @returns clusterId in queue
    */
    u64 assign_cluster_id( u64 orderId, u64 cluster_num );

    /*  check is queue has necessary number of keys which can be moved into backlog 
        or store it in memory
        @incoming set to true for incoming queue. Password and salt fields from AES_KeyStore 
                  should not be written in backlog for incoming (because absent).
        @returns true when part of keys moved into backlog and removed from queue
    */
    bool backlog( u64 id, bool incoming );

private:
    u32 keepNum_;
    std::string backlogName_;
    KeyStoresT backlog_;
    u32 nReserved_;
};

inline void KeyQueue::set_new_keepsize( u32 Kb )
{ 
    keepNum_ = (Kb << 10) / sizeof(KeyStoresT::value_type);
}

inline u32 KeyQueue::is_have_free() const { 
    i32 num = (i32)keepNum_ - KeyStoresT::size();
    if ( num < 0 )
        num = 0;
    return (u32)num; 
}

inline u32 KeyQueue::size() const
{ return KeyStoresT::size(); }

inline u32 KeyQueue::sizeInBytes() const
{ return (u32)KeyStoresT::size()*(sizeof(KeyStoresT::value_type)); }

inline KeyStoresT::iterator KeyQueue::begin()
{ return KeyStoresT::begin(); }

inline KeyStoresT::iterator KeyQueue::end()
{ return KeyStoresT::end(); }

inline void KeyQueue::clear_all( void ) { 
    KeyStoresT::clear(); 
}

/****************************************************/
class AES_KeyAgent : public Thread
{
public:
    AES_KeyAgent();

    /*  This is async operation. On first shutdown releases all used keys to database, after thread will stops.
        Call Thread::join() to wait a thread stopping.
    */
    void shutdown();

    /*  Thread::run() */
    virtual void run();

    /*   create and enqueue some amount of keys (see AES configuration) for presend action */
    void prepare_presend( void );

    /*  Get set of keys for outgoing pre-send
        @param keysSet the vector of keys to be filled
        @param num number of required keys 
    */
    void get_for_presend( AESPackagesT& keysSet, u32 num );

    /*  Get set of keys for crypto the outgoing message 
        @returns clusterId of key or UNASSIGNED_CLUSTER_ID if error
    */
    u64 get_for_crypto( AES_KeyStore* pKey );

    /*  Get set of keys for decrypto the incoming message
        @param pKey structure woth AES and IV to decrypto
        @param clusterId cluster Id of required key
    */
    void get_for_decrypto( AES_KeyStore* pKey, u64 clusterId );

    /*  Insert AES key or key IV data into incoming messages queue */
    void accept_incoming( const AESPackage& keyPackage );

    /*  Assign cluster number to key in the queue
        @param cluster_num number of OTP cluster what has the key 
        @param orderId order number of the key in queue
        @returns clusterId in queue
    */
    inline u64 assign_to_cluster( u64 orderId, u64 cluster_num ) {
        MGuard g(outLock_);
        interlockedInc( &outgoingKeysSent_ );
        return outgoing_->assign_cluster_id( orderId, cluster_num );
    }

/*********************************************************************/
    void createOutMagicQWord( const AES_KeyStore& keyStore );

    /*  Returns outgoing keys queue state */
    inline u32 get_outgoing_size( void );

    /*  Erase the key with 'clusterId' from outgoing queue to backup 
        Note: not used when proxy server or gateway emulation is enabled
    */
    void backupOutgoingKey( u64 clusterId );

    /*  Changes keep sizes for outgoing and incoming queues */
    void set_outgoing_keepsize(u32 mb);

    /*  Queues usage accessing (bytes) */
    inline i32 inQueueUsage( void ) const;
    inline i32 outQueueUsage( void ) const;
    inline void setInQueueUsage(u32 usage) const;
    inline void setOutQueueUsage(u32 usage) const;

    /*  Key counters accessing */
    inline u32 outKeysCreated( void ) const;
    inline u32 outKeysSent( void ) const;
    inline u32 inKeysReceived( void ) const;
    inline u32 inKeysApplied( void ) const;

    inline void interlockedInc( u32 volatile* ptrVal ) const;
    inline void interlockedAdd( u32 volatile* ptrVal, u32 num ) const;

private:
    Mutex outLock_;
    Mutex inLock_;
    Mutex shutdownLock_;

    bool shutdown_;

    /*  magic qword is making by first keys pre-send and using till the end of session */
    u64 magicOutQWord_;

    /* controls all async opearations */
    std::auto_ptr<Event> sync_;

    std::auto_ptr<KeyQueue> incoming_;
    std::auto_ptr<KeyQueue> outgoing_;

    /* the key queues usage */
    volatile u32 incomingQueueUsage_;
    volatile u32 outgoingQueueUsage_;

    /* the keys counters */
    volatile u32 outgoingKeysCreated_;
    volatile u32 outgoingKeysSent_;
    volatile u32 incomingKeysReceived_;
    volatile u32 incomingKeysApplied_;
};

inline u32 AES_KeyAgent::get_outgoing_size( void ) {
    MGuard g(outLock_);
    return outgoing_->size();
}

inline i32 AES_KeyAgent::inQueueUsage() const {
    if( incomingQueueUsage_ > 0x80000000 )
        throw Exception(getName() + " - FATAL: requested queue usage size is more than 2Gb");
    return incomingQueueUsage_;
}
inline i32 AES_KeyAgent::outQueueUsage() const {
    if( outgoingQueueUsage_ > 0x80000000 )
        throw Exception(getName() + " - FATAL: requested queue usage size is more than 2Gb");
    return outgoingQueueUsage_;
}

inline u32 AES_KeyAgent::outKeysCreated( void ) const 
{ return outgoingKeysCreated_; }

inline u32 AES_KeyAgent::outKeysSent( void ) const
{ return outgoingKeysSent_; }

inline u32 AES_KeyAgent::inKeysReceived( void ) const
{ return incomingKeysReceived_; }

inline u32 AES_KeyAgent::inKeysApplied( void ) const
{ return incomingKeysApplied_; }

inline void AES_KeyAgent::setInQueueUsage(u32 usage) const
{
#ifdef WIN32
    long volatile* ptrUsage = (long volatile*)&incomingQueueUsage_;
    InterlockedExchange( ptrUsage, static_cast<long>(usage) );
#else
    i32 volatile* ptrUsage = (i32 volatile*)&incomingQueueUsage_;
    *ptrUsage = usage;
#endif
}

inline void AES_KeyAgent::setOutQueueUsage(u32 usage) const
{
#ifdef WIN32
    long volatile* ptrUsage = (long volatile*)&outgoingQueueUsage_;
    InterlockedExchange( ptrUsage, static_cast<long>(usage) );
#else
    i32 volatile* ptrUsage = (i32 volatile*)&outgoingQueueUsage_;
    *ptrUsage = usage;
#endif
}

inline void AES_KeyAgent::interlockedInc( u32 volatile* ptrVal ) const 
{
#ifdef WIN32
    InterlockedIncrement( (long volatile*)ptrVal );
#else
    ++(*ptrVal);
#endif
}

inline void AES_KeyAgent::interlockedAdd( u32 volatile* ptrVal, u32 num ) const 
{
#ifdef WIN32
    InterlockedExchangeAdd( (long volatile*)ptrVal, static_cast<long>(num) );
#else
    (*ptrVal) += num;
#endif
}

class NotificationsMgrBase;

/****************************************************/
class AES_KeyExchange : public EnqueBufferSender, 
                        public Communicator
{
    friend class OTP_Processor;
public:
    /*  Constructor doesn't returns object while outgoing queue will be filled completely. */
    AES_KeyExchange(NotificationsMgrBase* notifier);
    virtual ~AES_KeyExchange();

    /*  Presend some amount of keys (see AES configuration) to Crypto2 
        @param numToPresend number of keys to presend
    */
    void presend( u32 numToPresend );

    /*  do_perform calls from AES_KeyExchange implementation be mean of ring buffer advancement 
        for incoming and outgoing messages
        @type is Gateway: incoming message received from the gateway policy
        @type is AES_Module: outgoing pre-send key message 
        @type is OTP_Module: incoming message what was enqueued from OTP de-cipherer
        @returns number of processed bytes, this number used to queue clearing
    */
    virtual u32 do_perform(const RawMessage& msg, Communicator::SenderType type);

    virtual Communicator::SenderType get_type( void )
    { return Communicator::AES_Module; }

    /*  Assign cluster number to key in the queue
        @param cluster_num number of OTP cluster what has the key 
        @param orderId order number of the key in queue
        @returns clusterId in queue
    */
    u64 assign_to_cluster( u64 orderId, u64 cluster_num );

    /*  Obtains module statistics */
    inline void getOtpInBuffersUsage( i32* bytes, i32* limit ) const;
    inline void getAesOutBuffersUsage( i32* bytes, i32* limit ) const;
    inline void getInkeyQueueUsage( i32* bytes, i32* limit ) const;
    inline void getOutkeyQueueUsage( i32* bytes, i32* limit ) const;
    inline u32 getOutgoingKeysCreated( void ) const;
    inline u32 getOutgoingKeysSent( void ) const;
    inline u32 getIncomingKeysReceived( void ) const;
    inline u32 getIncomingKeysApplied( void ) const;
    inline u32 getThroughput() const;

private:
    inline static void calcDecodeThroughput( u32 processed, u32 volatile* ptrVal );

    Mutex gatewayLock_;
    AES_KeyAgent keyagent_;

    volatile u32 throughput_;
    u32 aesKeyBundleSize_;
};

extern u32 GV_AesInBufferSize;
extern u32 GV_AesOutBufferSize;
extern u32 GV_AesInKeyStorageSize;
extern u32 GV_AesOutKeyStorageSize;

inline void AES_KeyExchange::getOtpInBuffersUsage( i32* bytes, i32* limit ) const {
    *bytes = getInBufferUsage();
    *limit = (GV_AesInBufferSize << 10);
}

inline void AES_KeyExchange::getAesOutBuffersUsage( i32* bytes, i32* limit ) const {
    *bytes = getOutBufferUsage();
    *limit = (GV_AesOutBufferSize << 10);
}

inline void AES_KeyExchange::getInkeyQueueUsage( i32* bytes, i32* limit ) const {
    *bytes = keyagent_.inQueueUsage();
    *limit = (GV_AesInKeyStorageSize << 10);
}

inline void AES_KeyExchange::getOutkeyQueueUsage( i32* bytes, i32* limit ) const {
    *bytes = keyagent_.outQueueUsage();
    *limit = (GV_AesOutKeyStorageSize << 10);
}

inline u32 AES_KeyExchange::getOutgoingKeysCreated() const
{ return keyagent_.outKeysCreated(); }

inline u32 AES_KeyExchange::getOutgoingKeysSent() const
{ return keyagent_.outKeysSent(); }

inline u32 AES_KeyExchange::getIncomingKeysReceived() const
{ return keyagent_.inKeysReceived(); }

inline u32 AES_KeyExchange::getIncomingKeysApplied() const
{ return keyagent_.inKeysApplied(); }

inline u32 AES_KeyExchange::getThroughput() const
{ return throughput_; }

/**/
#endif /* __aes_key_exchange_h__ */
