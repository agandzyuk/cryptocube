#ifndef __enque_buffer_sender_h__
#define __enque_buffer_sender_h__

#include "thread.h"
#include "mutex.h"
#include "eventp.h"
#include "raw_message.h"

#include <map>
#include <memory>

#define DEF_BUFFER_BLOCK_SIZE 0x1000 /* 64Kb */


class EnqueBufferSender;
class NotificationsMgrBase;

/***************************************************************************/
/*  Abstraction for the relationship between successors which are 
    participants of two-sided messaging 
*/
class Communicator
{
    friend class EnqueBufferSender;

public:
    enum SenderType
    {
        Invalid = 0,
        SSLChannelOne  = 1,
        SSLChannelTwo  = 2,
        Gateway_Module = 3,
        AES_Module     = 4,
        OTP_Module     = 5
    };

public:
    /*  Implementation should catches all exceptions and reports about
        @returns number of processed bytes, this number used to queue clearing
    */
    virtual u32 do_perform(const RawMessage& msg, SenderType type) = 0;

    /*  Implementation should provides the retreiving own sender type */
    virtual SenderType get_type( void ) = 0;
};

/***************************************************************************/
/*  Async buffer for incoming or outgoing messages */
class FifoBuffer : public Thread
{
public:
    FifoBuffer( const std::string& bufferName, EnqueBufferSender* owner );
    virtual ~FifoBuffer();

    /*  Starts the buffer controlling thread */
    void start( void );

    /*  Shutdowns the controlling thread */
    void shutdown( void );

    /*  Sync buffer processing and performs the messages flushing
        @note call perform() to restore messages processing after compete()
    */
    void complete( void );

    /*  Pauses or restores buffers processing after complete() calling */
    void perform( bool processing );

    /*  Returns buffer state */
    inline bool isBufferReady( void ) const;

    /*  Pushes data to queue
        @throws Exception when thread stopped, goes to stopping or not running yet
    */
    void enqueue( const RawMessage& msg );

    /*  Waiting for free space in case when buffer is full
        @param  nBytes orders the number of bytes that we want to write
        @returns false when thread stopped, goes to stopping or not running yet
    */
    bool waitReadyToWrite( u32 nBytes );

    /*  Setup the buffer size   */
    void setBufferSize(u32 kb);

    /*  Statistics for buffer usage */
    inline u32 getMessagesProcessed( void ) const;
    inline i32 getBufferUsage( void ) const;
    inline void setBufferUsage( i32 bytes );

protected:
    /* Thread::run implementation */
    virtual void run( void );

    /*  Returns buffer state without mutex locking */
    inline bool isBufferReadyNoLock( void ) const;

private:

    Mutex shutdownLock_;
    mutable Mutex qLock_;

    std::auto_ptr<Event> syncRead_;
    std::auto_ptr<Event> syncWrite_;
    RawMessagesQueueT queue_;

    bool shutdown_;
    bool isPerform_;

    EnqueBufferSender* owner_;

    i64 bufferSize_;
    u32 orderToWrite_;

    volatile i64 bufferUsage_;
    volatile u32 messagesProcessed_;
};

inline bool FifoBuffer::isBufferReadyNoLock() const {
    if( !isPerform_ ) return false;
    if( queue_.empty() ) return true;
    return (bufferSize_ + orderToWrite_) >= getBufferUsage();
}

inline bool FifoBuffer::isBufferReady() const {
    MGuard g(qLock_);
    return isBufferReadyNoLock();
}

inline u32 FifoBuffer::getMessagesProcessed() const { 
    return messagesProcessed_; 
}

inline i32 FifoBuffer::getBufferUsage() const {
    if( bufferUsage_ > (i64)0x80000000 )
        throw Exception(getName() + " - FATAL: requested buffer usage size is more than 2Gb (buffer usage limitation)");
    return (i32)bufferUsage_;
}

inline void FifoBuffer::setBufferUsage( i32 bytes ) {
    volatile i64* bufPtr = (volatile i64*)&bufferUsage_;
    *bufPtr = bytes;
}

/**********************************************************/
class EnqueBufferSender
{
    friend class FifoBuffer;

public:
    EnqueBufferSender( const std::string& name, 
                       NotificationsMgrBase* pNotifier,
                       Communicator::SenderType type );
    virtual ~EnqueBufferSender();

    /*  Set incoming buffer size
        @returns false when we have alloc exception
    */
    bool setInBufferSize(u32 kb);

    /*  Set incoming buffer size
        @returns false when we have alloc exception
    */
    bool setOutBufferSize(u32 kb);

    /*  Attaches incoming or outgoing communicator pointer */
    void attach(Communicator* pComm, bool incomingComm);

    /*  Detaches incoming or outgoing communicator pointer */
    void detach(bool incomingComm);

    /*  Starts buffers processing
        @notices on_perform() when ready to processing
    */
    virtual void start();

    /*  Synchronous shutting down */
    virtual void shutdown(void);

    /*  Waiting for free space in case when incoming buffer is full
        @param nBytes orders the number of bytes that we want to write
        @return false when buffer stopped, goes to stopping or not running yet
    */
    inline bool waitReadyToWriteIncoming( u32 nBytes );

    /*  Waiting for free space in case when incoming buffer is full
        @param nBytes orders the number of bytes that we want to write
        @return false when buffer stopped, goes to stopping or not running yet
    */
    inline bool waitReadyToWriteOutgoing( u32 nBytes );

    /*  Pushes data to incoming queue
        @param incoming message to enqueue
    */
    inline void enqueIncoming( const RawMessage& inMsg );

    /*  Pushes data to outgoing queue
        @param outgoing message to enqueue
    */
    inline void enqueOutgoing( const RawMessage& outMsg );

    /* */
    inline void enqueIncoming( const u8* buf, u32 size );
    inline void enqueOutgoing( const u8* buf, u32 size );

    /*  Statistics for buffer usage */
    inline u32 getInMessagesProcessed( void ) const;
    inline u32 getOutMessagesProcessed( void ) const; 
    inline i32 getInBufferUsage( void ) const;
    inline i32 getOutBufferUsage( void ) const;
    inline void setInBufferUsage( i32 bytes );
    inline void setOutBufferUsage( i32 bytes );    

protected:
    /*  Messages callback used in FifoBuffer */
    bool on_message(const RawMessage& msg, const FifoBuffer* self, Mutex* keepLock );

    /*  sender's identifiers */
    std::string name_;

    /*  for outer logging/info */
    NotificationsMgrBase* notifier_;

    Communicator::SenderType senderType_;

    /*  nearby module of incoming messages */
    Communicator* inComm_;

    /*  nearby module of outgoing messages */
    Communicator* outComm_;


private:
    std::auto_ptr<FifoBuffer> incomingBuffer_;
    std::auto_ptr<FifoBuffer> outgoingBuffer_;
};

/*********************************************************************/
inline void EnqueBufferSender::enqueIncoming( const u8* buf, u32 size ) { 
    assert( incomingBuffer_.get() && "EnqueBufferSender::enqueIncoming(buf,size) <null> object ptr!" );
    incomingBuffer_->enqueue( RawMessage(buf, size) ); 
}

inline void EnqueBufferSender::enqueOutgoing( const u8* buf, u32 size ) { 
    assert( outgoingBuffer_.get() && "EnqueBufferSender::enqueOutgoing(buf,size) <null> object ptr!" );
    outgoingBuffer_->enqueue( RawMessage(buf, size) ); 
}

inline void EnqueBufferSender::enqueIncoming( const RawMessage& msg ) { 
    assert( incomingBuffer_.get() && "EnqueBufferSender::enqueIncoming(msg) <null> object ptr!" );
    incomingBuffer_->enqueue( msg ); 
}

inline void EnqueBufferSender::enqueOutgoing( const RawMessage& msg ) { 
    assert( outgoingBuffer_.get() && "EnqueBufferSender::enqueOutgoing(msg) <null> object ptr!" );
    outgoingBuffer_->enqueue( msg ); 
}

inline bool EnqueBufferSender::waitReadyToWriteIncoming( u32 nBytes ) {
    assert( incomingBuffer_.get() && "EnqueBufferSender::waitReadyToWriteIncoming <null> object ptr!" );
    return incomingBuffer_->waitReadyToWrite( nBytes ); 
}

inline bool EnqueBufferSender::waitReadyToWriteOutgoing( u32 nBytes ) {
    assert( outgoingBuffer_.get() && "EnqueBufferSender::waitReadyToWriteOutgoing <null> object ptr!" );
    return outgoingBuffer_->waitReadyToWrite( nBytes ); 
}

inline u32 EnqueBufferSender::getInMessagesProcessed() const { 
    assert( incomingBuffer_.get() && "EnqueBufferSender::getInMessagesProcessed <null> object ptr!" );
    return incomingBuffer_->getMessagesProcessed(); 
}

inline u32 EnqueBufferSender::getOutMessagesProcessed() const { 
    assert( outgoingBuffer_.get() && "EnqueBufferSender::getOutMessagesProcessed <null> object ptr!" );
    return outgoingBuffer_->getMessagesProcessed(); 
}

inline i32 EnqueBufferSender::getInBufferUsage() const { 
    assert( incomingBuffer_.get() && "EnqueBufferSender::getInBufferUsage <null> object ptr!" );
    return incomingBuffer_->getBufferUsage(); 
}

inline i32 EnqueBufferSender::getOutBufferUsage() const { 
    assert( outgoingBuffer_.get() && "EnqueBufferSender::getOutBufferUsage <null> object ptr!" );
    return outgoingBuffer_->getBufferUsage(); 
}

inline void EnqueBufferSender::setInBufferUsage( i32 bytes ) { 
    assert( incomingBuffer_.get() && "EnqueBufferSender::setInBufferUsage <null> object ptr!" );
    incomingBuffer_->setBufferUsage( bytes ); 
}

inline void EnqueBufferSender::setOutBufferUsage( i32 bytes ) { 
    assert( outgoingBuffer_.get() && "EnqueBufferSender::setOutBufferUsage <null> object ptr!" );
    outgoingBuffer_->setBufferUsage( bytes ); 
}

/**/
#endif /* __enque_buffer_sender_h__ */
