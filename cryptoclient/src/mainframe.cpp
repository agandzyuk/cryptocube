#include "mainframe.h"
#include "socket_task.h"
#include "user_tasks.h"

using namespace std;

namespace {
    bool check_IP( const string& str_ip )
    {
        StringsT strs;
        if( 4 == split( str_ip, '.', &strs ) )
        {
            StringsT::iterator It = strs.begin();
            for( ; It != strs.end(); ++It )
            {
                if ( atoi( It->c_str() ) < 0 || atoi( It->c_str() ) > 255 )
                    break;
            }
            if( It == strs.end() )
            {
                return true;
            }
        }
        printf( "Incorrect IP address. Please retype: " );
        return false;
    }
}

Mainframe::Mainframe()
    : Thread("Mainframe"), 
    shutdown_(false),
    package_size_(DEF_PACKAGE_SIZE),
    send_interval_(DEF_SEND_INTERVAL),
    reconnect_interval_(DEF_RECONNECT_INTERVAL),
    silence_logging_(false),
    manual_tracing_(false)
{
    debug( "Created session: " + Time::timestamp() );
    IPAddress::init();
    start();
}

Mainframe::~Mainframe()
{
    shutdown();
}

void Mainframe::shutdown()
{
    timer_.cancel();
    timer_.join();

    MGuard guard( lock_ );
    shutdown_ = true;
    cancel();
}

void Mainframe::run()
{
    static u32 store_send_interval = send_interval_;

    int ch;
    char cryptobox_ip[100] = {0};
    /*printf("Please enter CryptoBox IP4 address before: ");


    do {
        scanf("%s", cryptobox_ip );
        cryptobox_ip[15] = 0;
    }
    while( !check_IP( cryptobox_ip ) );

    dispatcher_->set_gateway( cryptobox_ip, DEF_CRYPTOBOX_PORT );
*/
    do
    {
        fflush( stdin );
        ch = getch();
        printf("getch = %d\n", ch);
        ch = toupper(ch);
        switch( ch )
        {
        case 'N':
            {
#ifdef MYTEST
                u16 port = 5401;
                IPAddress local_addr = IPAddress::getByName("127.0.0.1")/*IPAddress::getLocalHost()*/;
                std::string str_addr = local_addr.getHostAddress();
                printf("New connection to localhost %s:%d\n", str_addr.c_str(), port );
                memcpy(cryptobox_ip, str_addr.c_str(), str_addr.length()+1);
#else
                set_silence_logging(true);
                printf("You choosen a new connection creation.\n"
                       "Please type the target IP address: ");
                do {
                    *cryptobox_ip = 0;
                    scanf("%s", cryptobox_ip );
                    cryptobox_ip[15] = 0;
                }
                while( !check_IP( cryptobox_ip ) && strlen(cryptobox_ip) );
                if ( strlen(cryptobox_ip) == 0 ) 
                {
                    printf("...request canceled\n");
                    set_silence_logging(false);
                    break;
                }
                i32 port;
                printf("Please type port number: ");
                scanf("%d", &port );
                if (port == 0 || port > 65534 )
                {
                    printf("Invalid port number\n...request canceled\n");
                    set_silence_logging(false);
                    break;
                }
#endif

                ConnectionTask* task = new ConnectionTask( string("connection-") + cryptobox_ip,
                                                           IPAddress::getByName( cryptobox_ip ),
                                                           port, this, this, (TCPConnection*)NULL );
                timer_.schedule( task, 50, reconnect_interval_ );
                set_silence_logging(false);
            }
            break;
        case 'X':
            {
                set_silence_logging(true);
                printf("You choosen connection stopping. Please type the target IP address: ");
                do {
                    *cryptobox_ip = 0;
                    scanf("%s", cryptobox_ip );
                    cryptobox_ip[15] = 0;
                }
                while( !check_IP( cryptobox_ip ) && strlen(cryptobox_ip) );
                if ( strlen(cryptobox_ip) == 0 ) 
                {
                    printf("...request canceled\n");
                    set_silence_logging(false);
                    break;
                }
                timer_.cancel(string("connection") + "-" + string(cryptobox_ip));
                
                Conn2FileT::iterator It = conn2filesMap_.begin();
                for(; It != conn2filesMap_.end(); ++It)
                    if ( It->first->get_target() == string(cryptobox_ip) )
                        break;
                
                if( It != conn2filesMap_.end() ) {
                    u32 fd = (u32)It->first->get_fd();
                    timer_.cancel("sendtask" + to_string(fd));
                    timer_.cancel("recvtask" + to_string(fd));
                    if( !It->first->is_disconnected() )
                    {
                        It->first->disconnect( Socket::BOTH );
                        printf("Connection %d is disconnected.\n", fd);
                    }
                    else
                        printf("Connection %d not connected and only reconnection process has stopped.\n", fd);
                    printf("You can restore connection by command 'R' by connection id.\n");
                }
                else
                    printf("Connection to %s not connected and only reconnection process has stopped.\n" 
                           "You can restore connection only through creation by command 'N'.\n", cryptobox_ip);

                set_silence_logging(false);
            }
            break;
        case 'T':
            if( !manual_tracing_ ) {
                printf("Switched the sending message tracing to manual. Press 'T' to send one message.\n");
                manual_tracing_ = true;
                store_send_interval = send_interval_;
                send_interval_ = 5;
            }
            else {
                /* to active connection */
                /* create_task( send_TaskSpec, NULL );*/
            }
            break;

        case 'R':
            {
                if( manual_tracing_ ) {
                    printf("Switched the sending message tracing to auto.\n");
                    send_interval_ = store_send_interval;
                    create_task( send_TaskSpec, NULL );
                    manual_tracing_ = false;
                    break;
                }

                set_silence_logging(true);
                printf("You choosen connection restoring by id. Connection id to restore is ");
                u32 id = 0;
                scanf("%d", &id);
                Conn2FileT::iterator It = conn2filesMap_.begin();
                for(; It != conn2filesMap_.end(); ++It)
                    if ( (u32)It->first->get_fd() == id )
                        break;
                if( It == conn2filesMap_.end() )
                {
                    printf("We have not already connected or disconnected connections with id %d.\n"
                           "...request canceled\n", id);
                    set_silence_logging(false);
                    break;
                }
                if( !It->first->is_disconnected() )
                {
                    printf("Connection %d already exists and keep a link with %s.\n"
                        "...request canceled\n", id, It->first->get_target().c_str() );
                    set_silence_logging(false);
                    break;
                }

                ConnectionTask* task = new ConnectionTask( string("connection-") + It->first->get_target(),
                                                           It->first->getIPAddress(),
                                                           It->first->get_port(),
                                                           this, 
                                                           this,
                                                           NULL );
                timer_.schedule( task, 50, reconnect_interval_ );
                set_silence_logging(false);
            }
            break;
        case 'S':
            set_silence_logging(true);
            printf("\nCurrent sending time interval is %u milliseconds.\n"
                   "Set the new sending time interval <enter>?\n", send_interval_);
            fflush(stdin); ch = getch();
            if( ch == SC_ENTER ) {
                printf("(No greater than 1 hour) New sending time interval (milliseconds) is ");
                u32 tme = 0; scanf("%d",&tme);
                if( tme < 3600 ) {
                    send_interval_ = tme; printf("OK\n"); ch = 0; 
                    store_send_interval = send_interval_;
                    set_silence_logging(false);
                    break;
                }
            }
            printf("...request canceled\n");
            ch = ch == 3 ? 'Q' : 0;
            set_silence_logging(false); 
            break;
        case 'I':
            set_silence_logging(true);
            printf("\nCurrent reconnecting time interval is %d seconds.\n"
                   "Set the new reconnecting time interval <enter>?\n", reconnect_interval_/1000);
            fflush(stdin); ch = getch();
            if( ch == SC_ENTER ) {
                printf("(No greater than 1 hour) New reconnecting time interval (seconds) is ");
                u32 tme = 0; scanf("%d",&tme);
                if( tme < 3600 ) {
                    reconnect_interval_ = tme * 1000; printf("OK\n"); ch = 0; 
                    set_silence_logging(false);
                    break;
                }
            }
            printf("...request canceled\n");
            ch = ch == 3 ? 'Q' : 0;
            set_silence_logging(false); 
            break;
        case 'P':
            set_silence_logging(true);
            printf("\nCurrent sending package size is %d bytes.\n"
                   "Set the new sending package size <enter>?\n", package_size_);
            fflush(stdin); ch = getch();
            if( ch == SC_ENTER ) {
                printf("New package size (bytes) is ");
                u32 sz = 0; scanf("%d",&sz);
                package_size_ = sz; printf("OK\n"); 
                set_silence_logging(false); ch = 0;
                break;
            }
            printf("...request canceled\n"); 
            ch = ch == 3 ? 'Q' : 0;
            set_silence_logging(false); 
            break;
        case 'F':
            {
                set_silence_logging(true);
                printf("You choosen an assigning the file to replay into connection with id.\n");
                printf("Please enter connection id: ");
                u32 id = 0;
                scanf("%d", &id);
                Conn2FileT::iterator It = conn2filesMap_.begin();
                for(; It != conn2filesMap_.end(); ++It)
                    if ( (u32)It->first->get_fd() == id )
                        break;
                if( It == conn2filesMap_.end() )
                {
                    printf("We have not already connected or disconnected connections with id %d.\n"
                           "...request canceled\n", id);
                    set_silence_logging(false);
                    break;
                }
                printf("Connection %d found. Now enter the path to replaying file: ", id);
                char buf[256] = {0}; scanf("%s",buf);
                if( strlen(buf) && !File::doesExist(buf) ) {
                    printf("Incorrect path was entered and file not exists.\n"
                           "...request canceled\n");
                    set_silence_logging(false);
                    break;
                }
                else {
                    It->second.reset( new LockedFile(buf, "r+") );
                    printf("%s is opened for reading. Sending will stopped after the entire content will be sent.\n", buf);
                }
            }
            set_silence_logging(false);
            break;
        case 'M':
            print_menu();
            break;
        case 'Q':
        case SC_CTRLC:
        case SC_CTRLZ:
        case SC_ESC:
            ch = 'Q';
            break;
        case 0:
            break;
        default:
            {
                char txt[2] = {0}; *txt = ch; printf("no command %s\n", txt);
            }
            break;
        }
        {
            MGuard guard( lock_ );
            if( shutdown_  ) ch = 'Q';
        }
        fflush(stdin);
    }
    while( ch != 'Q' && ch != SC_ESC );
    printf("\n...exiting Crypto Client.\n");
    sleep(2000);
}

Task* Mainframe::create_task( const TaskTypes type, TCPConnection* conn )
{
    static bool canceled = false;
    static TCPConnection* spActiveConnection = NULL;

    if( type == send_TaskType )
    {
        
        if( conn == NULL && spActiveConnection == NULL )
            return NULL;
        if( conn ) {
            spActiveConnection = conn;
            if( !manual_tracing_ ) 
                canceled = false;
        }

        if( conn && manual_tracing_ )
            return NULL;

        SendingTask* task = new SendingTask( "sendtask-" + to_string((u32)conn->get_fd()),
                                             conn2filesMap_[spActiveConnection].get(),
                                             package_size_, this, this, spActiveConnection );

        if( conn == NULL && manual_tracing_ && (canceled == false) ) {
            timer_.cancel( "sendtask-" + to_string((u32)spActiveConnection->get_fd()) );
            canceled = true;
        }

        timer_.schedule( task, send_interval_, 0 );
        return task;
    }
    else if( type == receive_TaskType )
    {
        RecvTask* task = new RecvTask( "recvtask-" + to_string((u32)conn->get_fd()), 
                                       this, this, conn );
        timer_.schedule( task, 0, 0 ); /* send_interval_ also used to buffer waiting */
        return task;
    }
    else if( type == connection_TaskType )
    {
        ConnectionTask* task = new ConnectionTask( "connection-" + conn->get_target(),
                                                   conn->getIPAddress(), conn->get_port(),
                                                   this, this, conn );
        timer_.schedule( task, 50, reconnect_interval_ ); /* pause to delete previous copy of task */
        return task;
    }
    return NULL;
}

void Mainframe::destroy_task( Task* task )
{
    timer_.cancel(task);
}
