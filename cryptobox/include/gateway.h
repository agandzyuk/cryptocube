#ifndef __gateway_h__
#define __gateway_h__

#include "refcounted.h"
#include "tunconnection.h" 
#include "gateway_policy.h" 
#include "server_socket.h"

#include <cassert>
#include <memory>

/**********************************************************/
#define  DEF_GATEWAY_IN_BUFFER_SIZE     0     /* not used */
#define  DEF_GATEWAY_OUT_BUFFER_SIZE    5120  /* 5 Mb */

/**********************************************************/
/*  Class Gateway
    CryptoBox Gateway service
*/
class NotificationsMgrBase;

class Gateway : public EnqueBufferSender, 
                public Communicator
{
public:
    /*  Constructor, destructor */
    Gateway(NotificationsMgrBase* notifier);
    virtual ~Gateway();

    /*  Initialize modules. Starts threads. */
    void initialize( void );

    /*  Sync start */
    void start( void );

    /*  Sync stop. Can be started by start() once again after stop(). */
    void stop( void );

    /*  Retreive TCP socket ptr. */
    TCPSockClient* getTcpSocket( void );

    /*  Get Gateway Policy. */
    GatewayPolicy* get_policy( void );

    /*  EnqueBufferSender::Communicator implementation */ 

    /*  do_perform calls from GatewayPolicy implementation be mean of ring buffer advancement
        for incoming and outgoing messages
        @param type is AES_Module: outgoing message what was enqueued from AES decoder
        @param type is Gateway: incoming message what was enqueued from Gateway socket
        @returns number of processed bytes, this number used to queue clearing
    */
    virtual u32 do_perform(const RawMessage& msg, SenderType type);

    virtual SenderType get_type( void )
    { return Communicator::Gateway_Module; }

private:

    std::auto_ptr<TCPSockServer> tcpServer_;
    std::auto_ptr<TCPSockClient> tcpClient_; 
    RefCountedPtr<TCPConnection> tcpConnection_;

    RefCountedPtr<TunConnection> sniffer_;

    std::auto_ptr<GatewayPolicy> policy_;
    bool started_;
};

/**/
#endif /* __proxy_server_h__ */
