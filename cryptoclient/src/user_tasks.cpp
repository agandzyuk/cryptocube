#include "user_tasks.h"
#include "system_exception.h"
#include "client_socket.h"
#include "connection.h"
#include "useful.h"
#include "notifications_mgr_base.h"

#include <algorithm>
#include <time.h>

using namespace std;

/****************************************************************/
ConnectionTask::ConnectionTask( const std::string& name,
                                const IPAddress& addr, 
                                u16 port,
                                TaskFactory* factory,
                                NotificationsMgrBase* notifyMgr,
                                TCPConnection* connection )
    : Task(name),
    addr_(addr),
    port_(port),
    factory_(factory),
    notifyMgr_(notifyMgr)
{
    if( connection )
        connection_.reset(connection);
}

ConnectionTask::~ConnectionTask()
{
}

void ConnectionTask::run()
{
    MGuard g( lock_ );

    std::string host_name = addr_.getHostAddress();

    TCPSockClient* s = NULL;
    if ( connection_.get() )
        s = connection_->get_socket();

    if( s && !s->is_open() )
    {
        try
        {
            connection_->reconnect();
        }
        catch(const Exception& ex)
        {
            notifyMgr_->warning( get_name() + " - WARNING: " + ex.what() );
            notifyMgr_->debug( get_name() + " - WARNING: " + ex.what() );
        }
        factory_->destroy_task( this );
    }
    else if ( s == NULL )
    {
        std::string except_txt;
        notifyMgr_->notify("Connecting to CryptoBox...\n");
        try {
            s = new TCPSockClient( addr_, port_ );
        }
        catch( const Exception& ex )
        {
            except_txt = ex.what();
        }

        if( s == NULL ) 
        {
            string msg = get_name() + " - WARNING: Failed to connect to CryptoBox on " + host_name + ":" + 
                 to_string(port_) + " - " + except_txt;
            notifyMgr_->warning( msg );
            notifyMgr_->debug( msg );
            return;
        }
    }

    connection_.reset( new TCPConnection( s, notifyMgr_) );
    g.release();


    string msg = get_name() + " - NOTE: We have Connection #" + to_string((u32)s->get_fd()) + " with CryptoBox on " + 
                     host_name + ":" + to_string(port_) + "!";
    notifyMgr_->notify( msg );
    notifyMgr_->debug( msg );

    factory_->create_task( send_TaskSpec, connection_.get() );
    factory_->create_task( receive_TaskSpec, connection_.get() );
    factory_->destroy_task( this );
}

/**************************************************************/
std::string SendingTask::latest_file;

SendingTask::SendingTask( const std::string& name,
                          LockedFile* sendfile,
                          u16 package_size,
                          TaskFactory* factory,
                          NotificationsMgrBase* notifyMgr,
                          TCPConnection* connection )
    : Task(name),
    package_size_(package_size),
    sendfile_(sendfile),
    factory_(factory),
    notifyMgr_(notifyMgr),
    outfile_(name + ".out"),
    shutdown_(false)
{
    connection_.reset( connection );
    time_t t;
    srand( time(&t) & 0xFF );
}

SendingTask::~SendingTask()
{
    MGuard g( lock_ );
    shutdown_ = true;
}


void SendingTask::run()
{
    MGuard g( lock_ );

    TCPSockClient* s = connection_->get_socket();
    if ( !s->is_open() )
    {
        notifyMgr_->debug( get_name() + " - WARNING: session was closed. Kill me, please!" );
        notifyMgr_->warning( get_name() + " - WARNING: session was closed. Kill me, please!" );
        factory_->destroy_task( this );
        return;
    }

    u8* buf = NULL;
    i32 read = 0;

    string notetag_inside;
    if( sendfile_ && !sendfile_->eof() )
    {
        if( latest_file.empty() ) 
        {
            string newfile = sendfile_->path();
            string::size_type pos = newfile.rfind('/');
            if( string::npos == pos )
                pos = newfile.rfind('\\');
            if( string::npos != pos )
            {
                notetag_inside = "<Hello. You must create new file /" + newfile.substr(++pos) + "/>";
            }
            latest_file = newfile;
        }
        buf = new u8[package_size_+notetag_inside.length()+1];
        if( !notetag_inside.empty() )
            memcpy(buf, notetag_inside.c_str(), notetag_inside.length() );
        read = sendfile_->read(buf+notetag_inside.length(), package_size_);
    }
    else
    {
        srand( time(0) );
        u16 pkgsz = rand();
        if( pkgsz < 21 )
            pkgsz += 20;

        buf = new u8[pkgsz+2];
        do { buf[read] = 48 + (rand() % 74); } 
        while( ++read < pkgsz );
    }
    g.release();

    bool except = false;
    if( read > 0 )
    {
        try
        {
            i32 write = read + notetag_inside.length();
            read = s->send( buf, write );
            if( read > 0 )
            {
                notifyMgr_->debug( get_name() + " - NOTE: sent " + to_string(read) + " bytes.");
                notifyMgr_->notify( get_name() + " - NOTE: sent " + to_string(read) + " bytes.");

                File f(outfile_, "ab+");
                f.write( buf, read );
            }
            else if ( sendfile_ && write > 0 )
                sendfile_->seek( -write, SEEK_CUR );
        }
        catch(const Exception& ex)
        {
            notifyMgr_->debug( get_name() + " - ERROR: " + ex.what() );
            notifyMgr_->error( get_name() + " - ERROR: " + ex.what() );
            connection_->disconnect(Socket::SEND);
            except = true;
        }
    }

    if( buf )
        delete[] buf;

    if( !except )
    {
        Task* task = factory_->create_task( send_TaskSpec, connection_.get() );
        if( task == NULL )
            connection_.abandon();
    }
    else
    {
        notifyMgr_->debug( get_name() + " - WARNING: has exception, so we suspend the sending to connection.");
        notifyMgr_->warning( get_name() + " - WARNING: has exception, so we suspend the sending to connection.");
    }
}

/**************************************************************/
RecvTask::RecvTask( const std::string& name,
                    TaskFactory* factory,
                    NotificationsMgrBase* notifyMgr,
                    TCPConnection* connection )
    : Task(name),
    factory_(factory),
    notifyMgr_(notifyMgr),
    infile_(name + ".in")
{
    connection_.reset( connection );
}

RecvTask::~RecvTask()
{}

void RecvTask::run()
{
try{
    MGuard g( lock_ );

    TCPSockClient* s = connection_->get_socket();
    if( s == NULL ) 
        return;

    if ( !s->is_open() )
    {
        notifyMgr_->debug( get_name() + " - WARNING: session was closed. Kill me, please!" );
        notifyMgr_->warning( get_name() + " - WARNING: session was closed. Kill me, please!" );
        factory_->destroy_task( this );
        return;
    }

    u8* buf = NULL;
    s8* buf2 = NULL;
    try 
    {
        s->set_nonblocking();
        i32 read = 65535;
        buf = new u8[65536];
        timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 200;
        s->untilReadyToRead(&timeout);
        read = s->recv( buf, read );
        if ( read > 0 )
        {
            i32 tagsize = strlen("<Hello. You must create new file /");
            if( read > tagsize )
            {
                if( 0 == strncmp((s8*)buf,"<Hello. You must create new file /",tagsize) )
                {
                    buf2 = strstr((s8*)buf+tagsize,"/>");
                    if ( buf2 )
                        *buf2 = 0;
                    buf2 += 2;
                    tagsize += buf2-(s8*)buf;
                    infile_ = (s8*)buf;
                }
            }
            
            notifyMgr_->debug( get_name() + " - NOTE: received " + to_string(read) + " bytes.");
            notifyMgr_->notify( get_name() + " - NOTE: received " + to_string(read) + " bytes.");
            File f(infile_, "ab+");
            if( buf2 )
                f.write( buf2, read-tagsize );
            else
                f.write( buf, read );
        }
    }
    catch(const Exception& ex)
    {}

    if( buf )
        delete[] buf;

    factory_->create_task( receive_TaskSpec, connection_.get() );
    }
catch(...)
{}
}
