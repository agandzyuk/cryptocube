#ifndef __ssl_tunnel_h__
#define __ssl_tunnel_h__

#include "ssl_connection_adapter.h"
#include "ssl_server_adapter.h"
#include "ssl_context.h"
#include "enque_buffer_sender.h"

#include "ipaddress.h"
#include "eventp.h"
#include "timer.h"
#include "task.h"

#define DEF_SSL_CERTIFICATE         "./ca.pem";
#define DEF_SSL_PRIVATE_KEY         "./ca.key"
#define DEF_SSL_PASSWORD            "CryptoBox"
#define DEF_SSL_VERIFY_PATH         "."
#define DEF_SSL_VERIFY_MODE         "none"

#define DEF_TUNNEL_IN_BUFFER_SIZE   5120    /* 5 Mb */
#define DEF_TUNNEL_OUT_BUFFER_SIZE  0       /* sync */

class SSL_Tunnel;
class NotificationsMgrBase;

/**********************************************************/
class ChannelObserver : public CryptoServer::Observer, 
                        public CryptoConnection::Observer
{
    friend class OTP_ProcessorBase;
    friend class SSL_Tunnel;
public:
    ChannelObserver(NotificationsMgrBase* pNotifier);
    /*  used for connection and disconnection synchronization */
    void join( void );

    inline CryptoConnection* channelOne( void ) {   
        MGuard g(lock_);
        return channelOne_; 
    }

    inline CryptoConnection* channelTwo( void ) { 
        MGuard g(lock_);
        return channelTwo_; 
    }

    bool isReady( void ) const { 
        MGuard g(lock_);
        return (channelOne_ && channelTwo_); 
    }

    void cancel( void ) {
        MGuard g(lock_);
        channelWaiter_.set();
    }

    void attach( EnqueBufferSender* comm ) {
        assert( comm_ == NULL && "ChannelObserver::attach Invalid routine usage!" );
        comm_ = comm;
    }

    void detach(void) {
        assert( comm_ && "ChannelObserver::detach Invalid routine usage!" );
        comm_ = NULL;
    }

protected:
    virtual bool on_connect(CryptoServer* server, CryptoConnection* connection );
    virtual void on_closed(CryptoServer* server, i32 error);

    virtual void on_connected(CryptoConnection* connection);
    virtual void on_disconnected(CryptoConnection* connection);
    virtual bool onReadyToRead(CryptoConnection* connection);
    virtual bool onReadyToWrite(CryptoConnection* connection);
    virtual void onConnectError(CryptoConnection* connection, i32 error, const std::string& description);
    virtual bool onWaitForReadyToWriteError(CryptoConnection* connection, i32 error, const std::string& description);
    virtual bool onWaitForReadyToReadError(CryptoConnection* connection, i32 error, const std::string& description);

private:
    mutable Mutex lock_;
    Event channelWaiter_;
    CryptoConnection* channelOne_;
    CryptoConnection* channelTwo_;

    EnqueBufferSender* comm_;

    /*  for outer logging/info */
    NotificationsMgrBase* notifier_;
};

/**************************************************************/
/*  Task is used by connection timer scheduling for first connect 
    or reconnect actions
*/
class ConnectionTask : public Task
{
public:
    ConnectionTask( const IPAddress& remoteIp, 
                    const IPAddress& interfaceIp,
                    u16 remotePort,
                    SSL_Tunnel* owner ); 
    virtual ~ConnectionTask();

protected:
    virtual void run( void );

private:
    IPAddress remoteIp_;
    IPAddress interfaceIp_;
    u16 remotePort_;
    SSL_Tunnel* owner_;
};

/**************************************************************/
class SSL_Tunnel : public EnqueBufferSender, 
                   public Communicator
{
    friend class ConnectionTask;
public:
    SSL_Tunnel(NotificationsMgrBase* pNotifier);
    virtual ~SSL_Tunnel();

    void initSSL();

    void cleanupSSL();

    CryptoServer* createSSLServer( const std::string& interfaceIp, 
                                   u16 port );

    /*  Asynchronous connection initiator   */
    void initSSLConnection( const IPAddress& remoteIp, 
                            const IPAddress& interfaceIp,
                            u16 remotePort );

    inline ChannelObserver* get_channel_observer( void )
    { return observer_.get(); }

    /*  Enques package from OTP module to sending into different channels
        @type equals OTP_Module: outgoing message which sends from OTP module
        @type equals SSL_ChannelOne or Two: outgoing message which enqueued inside SSL layer
        @returns number of processed bytes, this number used to queue clearing
        @note: using without waitReadyToWriteOutgoing, because EnqueBufferSender is used only 
        for SSL and OTP threads syncronization without buffering (SSL layer already has the buffering)
    */
    virtual u32 do_perform(const RawMessage& msg, SenderType type);

    virtual SenderType get_type( void )
    { return Communicator::OTP_Module; }

    void shutdown(void);

protected:
    /*  Synchronous connection 
        @returns true if connection succes
        @note: no exceptions
    */
    bool syncClientConnection( const IPAddress& remoteIp, 
                               const IPAddress& interfaceIp,
                               u16 remotePort );

    void configureSecureParams( void );

private:

    SSLSecureParam  secureParams_;
    std::auto_ptr<ChannelObserver> observer_;
    std::auto_ptr<SocketDispatcher> sslSocketDispatcher_;

    Timer connectionTimer_;
    SSLConnectionAdapter* pClient_;
    Mutex lock_;
    bool shutdown_;
};

/**/
#endif /* __ssl_tunnel_h__ */
