#ifndef __classes_h__
#define __classes_h__

#include "defines.h"
#include "enque_buffer_sender.h"
#include "notifications_mgr_base.h"
#include "ssl_tunnel.h"
#include "eventp.h"

/******************************************************************************/
class TestModule: public EnqueBufferSender,
                  public Communicator
{
public:
    TestModule( const std::string& moduleName, 
                NotificationsMgrBase* pNotifier,
                Communicator::SenderType type )
        : EnqueBufferSender(moduleName, pNotifier, type)
    {
        if( type == Communicator::Invalid ) 
        {
            waiter_.reset( new Event(false) ); 
            waiter_->reset();
        }
    }

    void send( const RawMessage& msg, bool incoming );
    void waitForRecv();

protected:
    void enqueue( const RawMessage& msg, bool incoming );

    /* virtuals from Communicator */
    virtual u32 do_perform( const RawMessage& msg, Communicator::SenderType from_there );

    virtual Communicator::SenderType get_type( void ) 
    { return senderType_; }

private:
    std::auto_ptr<Event> waiter_;
};


/**************************************************************/
/*  Testing SSL context from the locahost loopback connection */
class SSLStarter;

class SSLLoopback {
public:
    SSLLoopback(NotificationsMgrBase* pNotifier);
    ~SSLLoopback();
    
    SSL_Tunnel* getSSLTunnel( void ) 
    { return ssl_tunnel_; }
private:
    SSL_Tunnel* ssl_tunnel_;
    std::auto_ptr<SSLStarter> starter_;
};

/**************************************************************/

/*********************************************************************/
/*  Information output class */
class Notifier : public NotificationsMgrBase
{
public:

    Notifier()
    {}

    /*  NotificationsMgrBase implementation */
    void notify(const std::string& aNotification)
    { 
#ifdef WIN32
        char oembuf[512];
        *oembuf = 0;
        CharToOemBuff( aNotification.c_str(), oembuf, aNotification.length()+1);
        *const_cast<std::string*>(&aNotification) = oembuf;
#endif
        printf(aNotification.c_str()); 
    }

    void warning(const std::string& aNotification)
    { 
        notify("WARN: " + aNotification);
    }

    void error(const std::string& aNotification)
    { 
        notify("ERROR: " + aNotification);
    }

    void debug(const std::string& aNotification)
    {
        notify("DBG: " + aNotification);
    }

private:
};

#endif /** __classes_h__ */
