#include "test_defines.h"
#include "test_classes.h"
#include "configuration.h"
#include "aes_key_exchange.h"

/*  Linked externally */
bool GV_InNetworkHeadersLogging = false;
bool GV_OutNetworkHeadersLogging = false;
bool GV_NetworkDataLogging = false;
bool GV_OTPInLogging = true;
bool GV_OTPOutLogging = true;
bool GV_AESInLogging = true;
bool GV_AESOutLogging = true;
u32  GV_PackagePerKeySize = 4096;
u32  GV_PackagePerSocketBufferSize = 0;


/*  main app of tester */
int main()
{
    Notifier notifier;

    int ret = 0;

    printf("******************************************************************\n");
    printf("1. Sync EnqueBufferSender\n");
    printf("__________________________________________________________________\n");
    printf("Iterations:   30 000 messages\n");
    printf("Buffers size: 0 bytes\n");
    printf("Message size: 50 bytes\n");
    printf("__________________________________________________________________\n");

    ret = test_EnqueBufferSender(30000, 0, 0, &notifier);
    printf( (ret == 0) ? "\r\n\t\t\tPASS!\n\n" : "\r\n\t\t\tFAIL!\n\n" );
    if( ret ) return ret;

    printf("******************************************************************\n");
    printf("2. Async EnqueBufferSender\n");
    printf("__________________________________________________________________\n");
    printf("Iterations:   30 000 messages\n");
    printf("Buffers size: 1 Mb\n");
    printf("Message size: 50 bytes\n");
    printf("__________________________________________________________________\n");

    ret = test_EnqueBufferSender(30000, 1000, 0, &notifier);
    printf( (ret == 0) ? "\r\n\t\t\tPASS!\n\n" : "\r\n\t\t\tFAIL!\n\n" );
    if( ret ) return ret;

    printf("******************************************************************\n");
    printf("3. Async EnqueBufferSender with Huge messages\n");
    printf("__________________________________________________________________\n");
    printf("Options: each message is greater than used buffer size\n");
    printf("Iterations:   1000 messages\n");
    printf("Buffers size: 10 Kb\n");
    printf("Message size: 100 Kb\n");
    printf("__________________________________________________________________\n");

    ret = test_EnqueBufferSender(1000, 10, 100000, &notifier);
    printf( (ret == 0) ? "\r\n\t\t\tPASS!\n\n" : "\r\n\t\t\tFAIL!\n\n" );
    if( ret ) return ret;

    printf("******************************************************************\n");
    printf("4. Test OTP & SSL modules with cycling position requests\n");
    printf("__________________________________________________________________\n");
    printf("Options: image is lesser than positions request amount, SSL hangs on loopback\n");
    printf("Iterations  : 50 000 packages\n");
    printf("OTP image   : 10 Mb\n");
    printf("Package size: 10 Kb\n");
    printf("__________________________________________________________________\n");

    ret = test_OTP(1000, 10, 50000, &notifier);
    printf( (ret == 0) ? "\t\t\tPASS!\n\n" : "\t\t\tFAIL!\n\n" );
    fflush(stdout);
    if( ret ) return ret;

    return 0;
}
