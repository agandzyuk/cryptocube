#ifndef __gateway_policy_h__
#define __gateway_policy_h__

#include "tunconnection.h"
#include "enque_buffer_sender.h"

class Gateway;

class GatewayPolicy : public Communicator,
                      public Thread
{
public:
    friend class Gateway;
    friend class std::auto_ptr<GatewayPolicy>;

    virtual void start( void );
    virtual void shutdown( void );

protected:
    GatewayPolicy( const std::string& policy_name,
                   TCPConnection* connection,
                   NotificationsMgrBase* notifyMgr );

    GatewayPolicy( const std::string& policy_name,
                   TunConnection* connection,
                   NotificationsMgrBase* notifyMgr );

    GatewayPolicy( const std::string& policy_name,
                   NotificationsMgrBase* notifyMgr );

    virtual ~GatewayPolicy();

    /*  @throw Exception if failure initialization */
    void init();

    /*  Thread::run re-implementation */
    virtual void run( void );

    /*  socket/file listening */
    void receive( void );

    /*  attach gateway communicator */
    void attach( Communicator* comm );

    /*  detach gateway communicator */
    void detach(void);

    /*  Communicator implementation */ 

    /*  do_perform calls from GatewayPolicy implementation be mean of ring buffer advancement
        for incoming and outgoing messages
        @param type is AES_Module: outgoing message what was enqueued from AES decoder
        @returns number of processed bytes, this number used to queue clearing
    */
    virtual u32 do_perform(const RawMessage& msg, SenderType type);

    virtual SenderType get_type( void )
    { return Communicator::Gateway_Module; }

private:
    Mutex lock_;

    RefCountedPtr<TCPConnection> tcpConnection_;
    RefCountedPtr<TunConnection> tunConnection_;

    std::auto_ptr<Event> test_resume_event;

    NotificationsMgrBase* notifier_;
    Communicator* gateway_;

    bool shutdown_;
    RawMessagesT packages_;
};

/**/
#endif /* __gateway_policy_h__ */
