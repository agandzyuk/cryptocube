#ifndef __connection_h__
#define __connection_h__

#include <queue>

#include "mutex.h"
#include "client_socket.h"
#include "refcounted.h"
#include "message.h"

#define RCV_BUF_SIZE       65535 /* 65535 is the maximum value of window size. */

class NotificationsMgrBase;

/*  Base class for the Message splitter. Used in Connection::receive() 
    to split received buffer into several separate messages.
*/

typedef std::pair<s32,s32> MarkerT;
typedef std::vector<MarkerT> MarkersT;

typedef std::pair<u64,u64> Marker64T;
typedef std::vector<Marker64T> Markers64T;

class RawMessage;
typedef std::vector<RawMessage> RawMessagesT;

class SplitRawBufferToMessagesBase
{
public:

    virtual ~SplitRawBufferToMessagesBase(){}

    /*  Search for the packages in the buffer.
        @Returns the number of packages found.
    */
    virtual u16 operator()( const u8* pBuffer,
                            i32 bufferSize,
                            RawMessagesT* packages ) const = 0;

    /*  Returns true when splitter working with ethernet frames */
    virtual bool isEthernetSplitter( void ) const = 0;

    /* Auxiliary classes that represens execeptions that takes place during 
       handling of the garbled or zero messages.
    */
    class GarbledMsgReceivedException : public Exception {
    public: GarbledMsgReceivedException(const std::string& aReason) : Exception(aReason) {}
        inline const std::string& reason() const { return m_reason; }
    };
    class ZeroMsgReceivedException : public Exception {
    public: ZeroMsgReceivedException(const std::string& aReason) : Exception(aReason) {}
        inline const std::string& reason() const { return m_reason; }
    };
};

typedef struct MsgMark
{
    i32 msgBegin;
    i32 msgEnd;
    i32 bytesProcceed;

    MsgMark(i32 b = 0, i32 e = 0, i32 bytes = 0)
        :   msgBegin(b), msgEnd(e), bytesProcceed(bytes)
    {}
} 
MsgMark_;

/*  Represents transport layer. Incapsulates socket and contains queue of 
    the sending messages.
    @todo use a dedicated lock for reference counting.
*/
template<typename TSock>
class Connection: public RefCounted
{
public:

    static u8 ZeroMac[6];

    /*  @param apSock - socket of this connection (used to send and receive messages)
        @param notifyMng - logger used to notify about different events
        @param apSendSock - socket of this connection what used to send (then first param to receive)
    */
    Connection( ClientSocket<TSock>* apSock, 
                NotificationsMgrBase* notifyMng );

    /*  Returns the internal socket descriptor. */
    SD get_fd( void ) const;

    /*  Returns string representation of ip address */
    std::string get_target( void );

    /*  Returns the target ip address */
    IPAddress& getIPAddress( void );

    /*  Returns the used port */
    u16 get_port( void );

    /*  Returns the corresponding socket.   */ 
    ClientSocket<TSock>* get_socket( void );

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


    /*  Disconnects the connection.
        @param how - the way of the socket disconnection
        Syncronized.
     */
    void disconnect( Socket::How how );

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
    bool is_disconnected( void );

    /*
      Clears the sending message queue.
      Helper function.
     */
    void clear( void );

    /*  The member replaces the stored socket pointer with a null pointer and returns 
        the previously stored pointer to socket.
        You must not call any connection method after this method. 
    */
    ClientSocket<TSock>* release_socket( void );

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
    virtual ~Connection();

    /*  The socket of this connection.  */
    ClientSocket<TSock>* pSocket_;

private:
    /* Mutex - protects buffer */
    Mutex lock_;  

    /*  Buffer - contains the data received earlier (if any).   */
    Message buffer_;

    /*  true if the connection is disconnected, false - otherwise.  */
    bool isDisconnected_;

    /*  notification manager    */
    NotificationsMgrBase* notifyMng_;
    
    /*  target ip address */
    IPAddress addr_;

    /*  string representation */
    std::string addrStr_;

    /*  target port */
    u16 port_;
};

typedef Connection<TCPSocket> TCPConnection;
typedef Connection<RawSocket> RawConnection;

#endif /* __connection_h__ */


