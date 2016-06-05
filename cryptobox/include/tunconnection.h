#ifndef __tun_connection_h__
#define __tun_connection_h__

#include "tundevice.h"
#include "connection.h"

class TunConnection: public RefCounted
{
public:
    /*  @param notifyMng - logger used to notify about different events */
    TunConnection( NotificationsMgrBase* notifyMng );

    /*  Returns the internal TUN device descriptor. */
    SD get_fd( void ) const;

    /*  Returns the target ip address */
    IPAddress& getIPAddress( void );

    /*  Sends the given message to communication link.
        @param splitter - functor that able to split send buffer into several messages
        @param apMsg - buffer that contains message to send
        @param aSize - size of the message
        @return the number of bytes that were sent, 0 if an error of EWOULDBLOCK was returnd.
     */
    i32 send( const SplitRawBufferToMessagesBase &splitter, 
              const RawMessage& msg );

    /*  Receives some bytes from communication link, then convert them to RawMsg.
        @param splitter - functor that able to split recevied buffer into several messages
        @return the number of received RawMsgs.
     */
    i32 receive( const SplitRawBufferToMessagesBase& splitter,
                 RawMessagesT* messages );

    /*  Create TunTap connection.
        @param tunName Interface name
     */
    void connect( const std::string& tunName );

    /*  Disconnects the connection.
        @param how - the way of the socket disconnection
        Syncronized.
     */
    void disconnect( void );

    /*  Reconnects the connection in condition if connection is lost.
        @returns true if reconnect is successfull
        @throw Exception
        Syncronized.
     */
    void reconnect( void );

    /*
      Returns true if the connection is disconnected, otherwise - false.
      @note synchronized.
     */
    inline bool is_disconnected( void )
    {
        MGuard g(lock_);
        return isDisconnected_;
    }


    /*
      Clears the sending message queue.
      Helper function.
     */
    void clear( void );

    /*  Blocks until the device is ready to read.
        @return true when device to read, false when timeout ends
    */
    inline bool untilReadyToRead( struct timeval* timeout = NULL );

    /*  Blocks until the device is ready to write.
	    @return true when device to write, false when timeout ends
    */
    inline bool untilReadyToWrite( struct timeval* timeout = NULL );


#ifdef _DEBUG
    virtual s32 add_ref( void ) const
    {
        return RefCounted::add_ref();
    }
    
    virtual s32 release( void ) const
    {
        return RefCounted::release();
    }
#endif

private:
    /* Destructor. User must only use release() to delete the connection. */
    virtual ~TunConnection();

    /*  Connection object.  */
    std::auto_ptr<TunDevice> apTun_;

private:
    /* Mutex - protects buffer */
    Mutex lock_;

    /*  Buffer - contains the data received earlier (if any).   */
    Message buffer_;

    /*  true if the connection is disconnected, false - otherwise.  */
    bool isDisconnected_;

    /*  notification manager    */
    NotificationsMgrBase* notifyMng_;
};

inline bool TunConnection::untilReadyToRead( struct timeval* timeout )
{
    assert( apTun_.get() );
    return apTun_->untilReadyToRead(timeout);
}

inline bool TunConnection::untilReadyToWrite( struct timeval* timeout )
{
    assert( apTun_.get() );
    return apTun_->untilReadyToWrite(timeout);
}

#endif /* __tun_connection_h__ */
