#ifndef __defines_h__
#define __defines_h__

#ifndef MYUNITTEST
#define MYUNITTEST 1
#endif

#include <sys/stat.h>
#include <string>

#include "mutex.h"
using namespace std;

extern Mutex consoleLock;

/*  UI message which notify about the possible test hanging */
void progress(bool start = false);

/*  Cases */
class NotificationsMgrBase;

int test_EnqueBufferSender(u32 nMessages, u32 kbBufferSize, u32 nMessageSize, NotificationsMgrBase* pNotifier);
int test_OTP(u32 nMessages, u32 otp_size_mb, u32 nMessageSize, NotificationsMgrBase* pNotifier);



#endif /** __defines_h__ */
