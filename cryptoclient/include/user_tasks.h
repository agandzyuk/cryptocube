#ifndef __user_tasks_h__
#define __user_tasks_h__

#include "mainframe.h"
#include "task.h"
#include "connection.h"
#include "ipaddress.h"
#include "refcounted.h"
#include "useful.h"
#include "lockedfile.h"

class NotificationsMgrBase;

/* performs new connection or reconnects existant */
class ConnectionTask : public Task, public RefCounted
{
    friend class Mainframe;
protected:
    ConnectionTask( const std::string& name,
                    const IPAddress& addr, 
                    u16 port, 
                    TaskFactory* factory,
                    NotificationsMgrBase* notifyMgr,
                    TCPConnection* pConnection );
    ~ConnectionTask();

    virtual void run( void );

private:
    Mutex     lock_;
    IPAddress addr_;
    u16       port_;
    TaskFactory* factory_;
    NotificationsMgrBase* notifyMgr_;
    RefCountedPtr<TCPConnection> connection_;
};

/* performs sending periodically */
class SendingTask : public Task, public RefCounted
{
    friend class Mainframe;
protected:
    SendingTask( const std::string& name,
                 LockedFile* sendfile,
                 u16 package_size,
                 TaskFactory* factory,
                 NotificationsMgrBase* notifyMgr,
                 TCPConnection* connection );
    ~SendingTask();

    virtual void run( void );

private:
    Mutex lock_;
    u16 package_size_;

    LockedFile* sendfile_;
    RefCountedPtr<TCPConnection> connection_;
    TaskFactory* factory_;
    NotificationsMgrBase* notifyMgr_;
    std::string outfile_;
    static std::string latest_file;
    bool shutdown_;
};

/* performs data receiving */
class RecvTask : public Task, public RefCounted
{
    friend class Mainframe;
protected:
    RecvTask( const std::string& name,
              TaskFactory* factory,
              NotificationsMgrBase* notifyMgr,
              TCPConnection* connection );
    ~RecvTask();

    virtual void run( void );

private:
    Mutex lock_;
    RefCountedPtr<TCPConnection> connection_;
    TaskFactory* factory_;
    NotificationsMgrBase* notifyMgr_;
    std::string infile_;
};

#endif /*__user_tasks_h__ */
