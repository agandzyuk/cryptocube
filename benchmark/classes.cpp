#include "classes.h"
#include "configuration.h"

using namespace std;

/***********************************************************/
/*  Unlinked externals */
u16 GV_SSLServerPort = 5403;
u16 GV_SSLRemotePort = 5403;
std::string GV_ChannelEth1 = "127.0.0.1";
std::string GV_ChannelEth2 = "127.0.0.1";
std::string GV_RemoteIP    = "127.0.0.1";

/***********************************************************/
/*  Helpers */
Mutex consoleLock;

void progress(bool start)
{
    static u32 meter = 0;
    MGuard g(consoleLock);

    if(start)
        meter = 0;
    u32 c = (meter % 4001);
    if( c == 1000 )
        printf("\r|");
    else if( c == 2000 )
        printf("\r/");
    else if( c == 3000 )
        printf("\r-");
    else if( c == 4000 )
        printf("\r\\");
    ++meter;
}


/***********************************************************/
u32 TestModule::do_perform( const RawMessage& msg, 
                            Communicator::SenderType from_there ) 
{
    /* notifications mapper */
    std::string from("None");
    switch(from_there)
    {
    case Invalid:
        //printf( "%s: Message received from Socket\n", name_.c_str() );
        progress();
        if( senderType_ == Gateway_Module )
            enqueue( msg, false );
        else if( senderType_ == SSLChannelOne )
            enqueue( msg, true );
        break;
    case Gateway_Module:
        //printf( "%s: Message received from Gateway\n", name_.c_str() );
        progress();
        if( senderType_ == AES_Module )
            enqueue( msg, false );
        else if( senderType_ == Invalid )
            waiter_->set();
        break;
    case AES_Module:
        from = "AES_Module";
        //printf( "%s: Message received from AES_Module\n", name_.c_str() );
        progress();
        if( senderType_ == OTP_Module )
            enqueue( msg, false );
        else if( senderType_ == Gateway_Module )
            enqueue( msg, true );
        break;
    case OTP_Module:
//        printf( "%s: Message received from OTP_Module\n", name_.c_str() );
        progress();
        if( senderType_ == SSLChannelOne )
            enqueue( msg, false );
        else if( senderType_ == AES_Module )
            enqueue( msg, true );
        break;
    case SSLChannelOne:
    case SSLChannelTwo:
        progress();
//        printf( "%s: Message received from SSLTunnel\n", name_.c_str() );
        if( senderType_ == Invalid )
            waiter_->set();
        else if( senderType_ == OTP_Module )
            enqueue( msg, true );
        break;
    }

    return msg.size();
}


void TestModule::send( const RawMessage& msg, bool incoming )
{ 
//    printf("%s: Sending message\n", name_.c_str() );
    progress();
    if( incoming && inComm_ ) {
        static_cast<TestModule*>(inComm_)->waitReadyToWriteOutgoing( msg.size() );
        static_cast<TestModule*>(inComm_)->do_perform( msg, get_type() );
    }
    else if( !incoming && outComm_ ) {
        static_cast<TestModule*>(outComm_)->waitReadyToWriteIncoming(  msg.size() );
        static_cast<TestModule*>(outComm_)->do_perform( msg, get_type() );
    }
}

void TestModule::enqueue( const RawMessage& msg, bool incoming )
{ 
    progress();
    if( incoming ) {
        waitReadyToWriteIncoming( msg.size() );
        enqueIncoming( msg );
    }
    else {
        waitReadyToWriteOutgoing(  msg.size() );
        enqueOutgoing( msg );
    }
}

void TestModule::waitForRecv()
{ 
    if( senderType_ == Communicator::Invalid ) {
        waiter_->wait(); 
        waiter_->reset(); 
    }
}

/**********************************************************************/
/*  SSLStarter thread */
class SSLStarter : public Thread
{
public:
    SSLStarter(SSL_Tunnel* ssl) : ssl_(ssl), shutdown_(false)
    {}
    void shutdown(void);

    bool is_running(void)
    {
        MGuard guard( lock_ );
        return running_;
    }

protected:
    virtual void run(void);

private:
    Mutex lock_;
    SSL_Tunnel* ssl_;
    bool  shutdown_;
    bool  running_;
};

void SSLStarter::run()
{
    try
    {
        bool retry = true;
        while( retry )
        {
            Thread::sleep(200);

            if( ssl_->get_channel_observer()->isReady() )
            {
                MGuard guard(lock_);
                shutdown_ = true;
                running_  = true;
                ssl_->get_channel_observer()->channelOne()->waitForReadyToRead(true);
                ssl_->get_channel_observer()->channelTwo()->waitForReadyToRead(true);
            }

            MGuard guard(lock_);
            retry = !shutdown_;
        }
    }
    catch(const SSLException& ex)
    {
        printf(">> SSL ERROR: %s\n", ex.what());
        assert(!">> SSL Exception!");
    }
    catch(const Exception& ex)
    {
        std::string msg = ex.what();
    #ifdef WIN32
        char oembuf[512] = {0};
        CharToOemBuff( msg.c_str(), (LPSTR)oembuf, msg.length()+1 );
        msg = oembuf;
    #endif
        printf(">> ERROR: %s\n", msg.c_str() );
        assert(!">> Exception!");
    }
    catch(const std::exception& ex)
    {
        printf(">> std::exception %s\n", ex.what());
        assert(!">> std::exception!");
    }
    catch(...)
    {
        printf(">> Unexpected exception!\n");
        assert(!">> Unexpected exception!");
    }
}

void SSLStarter::shutdown()
{
    Mutex lock_;
    shutdown_ = true;
    running_  = false;
}

/***********************************************************/
SSLLoopback::SSLLoopback(NotificationsMgrBase* pNotifier)
    : ssl_tunnel_(NULL)
{
    ssl_tunnel_ = new SSL_Tunnel(pNotifier);
    if( ssl_tunnel_ == NULL )
        throw Exception("Can't create SSL Tunnel instance");
    ssl_tunnel_->initSSL();

    starter_.reset( new SSLStarter(ssl_tunnel_) );
    starter_->start();

    CryptoServer* channelOne = ssl_tunnel_->createSSLServer( GV_ChannelEth1, GV_SSLServerPort );
    if( channelOne == NULL )
        throw Exception("Can't create SSL server channel");
    channelOne->init();

    ssl_tunnel_->initSSLConnection( IPAddress::getByName(GV_RemoteIP),
                                    IPAddress::getByName(GV_ChannelEth2),
                                    GV_SSLRemotePort );
    ssl_tunnel_->get_channel_observer()->join();
    starter_->join();
}

SSLLoopback::~SSLLoopback()
{
    if( starter_.get() && starter_->is_running() ) {
        starter_->shutdown();
        starter_->join();
    }
    ssl_tunnel_->cleanupSSL();
    delete ssl_tunnel_;
}
