#ifndef __mainframe_h__
#define __mainframe_h__

#include "thread.h"
#include "notifications_mgr_base.h"
#include "lockedfile.h"
#include "boxtime.h"
#include "timer.h"
#include "task.h"
#include "connection.h"

#include <map>

#define DEF_SEND_INTERVAL      4000
#define DEF_PACKAGE_SIZE       20000
#define DEF_RECONNECT_INTERVAL 8000


extern void print_menu();

typedef int TaskSpec;
const TaskSpec invalid_TaskSpec    = 0;
const TaskSpec receive_TaskSpec    = 1;
const TaskSpec send_TaskSpec       = 2;
const TaskSpec connection_TaskSpec = 3;
const TaskSpec newInLink_TaskSpec  = 4;

class TaskFactory
{
public:
    virtual Task* create_task( const TaskSpec type, TCPConnection* conn ) = 0;
    virtual void destroy_task( Task*task ) = 0;
};


class Mainframe : public Thread, 
                  public TaskFactory, 
                  public NotificationsMgrBase
{
public:
    Mainframe();
    ~Mainframe();
    void shutdown( void );

    Task* create_task( const TaskSpec type, TCPConnection* conn );
    void destroy_task( Task* task );

    void set_silence_logging(bool silence) {
        silence_logging_ = silence;
    }

protected:
    virtual void run( void );

    virtual void notify(const std::string& aNotification)
    { 
#ifdef WIN32
        char oembuf[512];
        *oembuf = 0;
        CharToOemBuff( aNotification.c_str(), oembuf, aNotification.length()+1);
        *const_cast<std::string*>(&aNotification) = oembuf;
#endif
        if ( !silence_logging_ ) 
            printf("%s\n", aNotification.c_str() ); 
    }

    /*  Notifies about the warning
        @param  aNotification - warning message
     */
    virtual void warning(const std::string& aNotification)
    { 
#ifdef WIN32
        char oembuf[512];
        *oembuf = 0;
        CharToOemBuff( aNotification.c_str(), oembuf, aNotification.length()+1);
        *const_cast<std::string*>(&aNotification) = oembuf;
#endif
        if ( !silence_logging_ ) 
            printf("%s\n", aNotification.c_str() ); 
    }

    /*  Notifies about the error
        @param  aNotification - error message
     */
    virtual void error(const std::string& aNotification)
    { 
#ifdef WIN32
        char oembuf[512];
        *oembuf = 0;
        CharToOemBuff( aNotification.c_str(), oembuf, aNotification.length()+1);
        *const_cast<std::string*>(&aNotification) = oembuf;
#endif
        if ( !silence_logging_ ) printf("%s\n", aNotification.c_str() ); 
    }

    virtual void debug(const std::string& aNotification)
    {
        std::auto_ptr<File> debug_file;
        try {
            debug_file.reset( new File("./client.log", "a+") );
        }
        catch( const Exception& ex)
        {
            std::string except = "Can't open file ./client.log: ";
#ifdef WIN32
            char oembuf[512];
            *oembuf = 0;
            CharToOemBuff( ex.what(), oembuf, aNotification.length()+1);
            except += oembuf;
#endif
            printf("%s\n", except.c_str());
            return;
        }
        
        debug_file->write( aNotification.c_str(), aNotification.length() );
        debug_file->write( "\n", 1 );
    }

private:
    typedef std::map< TCPConnection*,RefCountedPtr<LockedFile> > Conn2FileT;

    Conn2FileT conn2filesMap_;
    Timer timer_;

    bool shutdown_;
    Mutex lock_;
    Mutex file_lock_;
    u32   package_size_;
    u32   send_interval_;
    u32   reconnect_interval_;

    bool silence_logging_;
    bool manual_tracing_;
};

#endif /* __mainframe_h__ */


