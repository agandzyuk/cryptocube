#include "test_classes.h"

using namespace std;

const char szTestMsgText[] = "Simple;*Test%$#Message!@#With*&^Text*)(*&Random+_)~Data";
static RawMessage g_enq_test_msg( (const u8*)szTestMsgText, sizeof(szTestMsgText));

/***********************************************************/
int test_EnqueBufferSender(u32 nMessages, 
                           u32 kbBufferSize, 
                           u32 nMessageSize,
                           NotificationsMgrBase* pNotifier)
{
    try {
        if( nMessageSize ) {
            g_enq_test_msg = RawMessage(nMessageSize);
            for(u32 i = 0; i < nMessageSize/2; ++i )
                *(u16*)(g_enq_test_msg.get() + i*2) = rand();
        }

        printf("Create modules ...\n");
        TestModule start( "Socket", pNotifier, Communicator::Invalid);
        TestModule gateway( "TestGateway", pNotifier, Communicator::Gateway_Module );
        TestModule aes( "TestAes", pNotifier,  Communicator::AES_Module);
        TestModule otp( "TestOtp", pNotifier, Communicator::OTP_Module );
        TestModule tunnel( "TestTunnel", pNotifier, Communicator::SSLChannelOne );
        TestModule finish( "SSL", pNotifier, Communicator::Invalid );

        gateway.setInBufferSize(kbBufferSize);
        gateway.setOutBufferSize(kbBufferSize);
        aes.setInBufferSize(kbBufferSize);
        aes.setOutBufferSize(kbBufferSize);
        otp.setInBufferSize(kbBufferSize);
        otp.setOutBufferSize(kbBufferSize);
        tunnel.setInBufferSize(kbBufferSize);
        tunnel.setOutBufferSize(kbBufferSize);

        start.attach( &gateway, true );
        start.attach( &gateway, false );
        gateway.attach( &start, true );
        gateway.attach( &aes, false );
        aes.attach( &gateway, true );
        aes.attach( &otp, false );
        otp.attach( &aes, true );
        otp.attach( &tunnel, false );
        tunnel.attach( &otp, true );
        tunnel.attach( &finish, false );
        finish.attach( &tunnel, true );
        finish.attach( &tunnel, false );
        printf("OK\n");

        printf("Starting threads ...\n");
        progress(true);

        start.start();
        gateway.start();
        aes.start();
        otp.start();
        tunnel.start();
        finish.start();
        Thread::sleep(50);
        printf("\rOK\n");

        printf("Process test ...\n");
        u32 i = 0;
        for( i = 0; i < nMessages; i++ )
        {
            start.send(g_enq_test_msg, true);
        }
        finish.waitForRecv();

        for(i = 0; i < nMessages; i++ )
        {
            finish.send(g_enq_test_msg, false);
        }
        start.waitForRecv();
        {
            MGuard g(consoleLock);
            printf("\rOK\n");
            printf("Shutting down ...\n");
        }

        finish.shutdown();
        tunnel.shutdown();
        otp.shutdown();
        aes.shutdown();
        gateway.shutdown();
        start.shutdown();

        start.detach( true );
        start.detach( false );
        gateway.detach( true );
        gateway.detach( false );
        aes.detach( true );
        aes.detach( false );
        otp.detach( true );
        otp.detach( false );
        tunnel.detach( true );
        tunnel.detach( false );
        finish.detach( true );
        finish.detach( false );
    }
    catch( const Exception& ex ) { 
        printf("Exception: %s", ex.what() );
        return -1; 
    }
    catch( const std::exception& ex ) { 
        printf("STD exception: %s", ex.what() );
        return -1; 
    }
    catch( ... ) { 
        printf("Unhandled exception!");
        return -1; 
    }
    return 0;
}
