#include "classes.h"
#include "otp_base.h"
#include "configuration.h"

static AESPackage g_test_pkg;

/***********************************************************/
int test_OTP(u32 nMessages, 
             u32 otp_size_mb, 
             u32 nMessageSize,
             NotificationsMgrBase* pNotifier)
{
    int ret = 0;
    u8* rnd_content = NULL;
    try {
        printf("Creating OTP image file %s, size %d Mb ...\n", GV_OtpImagePath.c_str(), otp_size_mb);
        //GV_OtpImagePath = OTP_POSITIONING_FILENAME;

        OTP_Processor::createImage(GV_OtpImagePath, otp_size_mb);
        File tmp_img;
        tmp_img.open(GV_OtpImagePath,"rb");
        tmp_img.close();

        printf("Creating test array %d keys ...\n", nMessages);
        rnd_content = new u8[nMessageSize];
        for(u32 i = 0; i < nMessageSize/2; ++i )
            *(u16*)(rnd_content + i*2) = rand();

        vector<AES_KeyStore> keys;
        for( u32 i = 0; i < nMessages; ++i ) {
            AES_KeyStore newKeystore;
            AES_KeyGenerator( &newKeystore );
            keys.push_back( newKeystore );
        }
        printf("OK\n");

        printf("Creating OTP Processor ...\n");
        OTP_Processor otp(pNotifier);
        otp.init_otp_outgoing();

        TestModule aes( "TestAes", pNotifier, Communicator::AES_Module);

        aes.setInBufferSize(1000);
        aes.setOutBufferSize(1000);
        otp.setInBufferSize(1000);
        otp.setOutBufferSize(1000);

        printf("Creating SSL Loopback tunnel ...\n");
        SSLLoopback ssl(pNotifier);
        printf("OK\n");

        aes.attach( &otp, true );
        aes.attach( &otp, false );
        otp.attach( &aes, true );
        otp.attach( ssl.getSSLTunnel(), false );

        //ssl.getSSLTunnel()->attach( &otp, true );
        ssl.getSSLTunnel()->attach( &otp, false );
        printf("OK\n");

        printf("Starting threads ...\n");

        progress(true);

        ssl.getSSLTunnel()->start();
        aes.start();
        otp.start();
        Thread::sleep(50);
        printf("\rOK\n");

        printf("Process test ...\n");
        u32 i = 0;

        vector<AES_KeyStore>::iterator key_It = keys.begin();
        for( i = 0; i < nMessages; i++ )
        {
            auto_ptr<AESPackage> pkg( AESPackage::makeCRData( *key_It, RawMessage(rnd_content, nMessageSize), (u64)i) );
            aes.send( *pkg.get(), true );
            key_It++;
        }
        aes.waitForRecv();

        {
            MGuard g(consoleLock);
            printf("\rOK\n");
            printf("Shutting down ...\n");
        }

        aes.detach( true );
        aes.detach( false );
        otp.detach( true );
        otp.detach( false );
        ssl.getSSLTunnel()->detach(false);

        aes.shutdown();
        otp.shutdown();
    }
    catch( const Exception& ex ) { 
        printf("Exception: %s", ex.what() );
        ret = -1; 
    }
    catch( const std::exception& ex ) { 
        printf("STD exception: %s", ex.what() );
        ret = -1; 
    }
    catch( ... ) { 
        printf("Unhandled exception!");
        ret = -1; 
    }

    if( rnd_content )
        delete[] rnd_content;

    printf("Delete temporary files.\n");
    if( File::doesExist(GV_OtpImagePath) )
        File::deleteFile(GV_OtpImagePath);

    if( File::doesExist("./otp.in") )
        File::deleteFile("./otp.in");

    if( File::doesExist("./otp.out") )
        File::deleteFile("./otp.out");

    if( File::doesExist(OTP_POSITIONING_FILENAME) )
        File::deleteFile(OTP_POSITIONING_FILENAME);

    return ret;
}
