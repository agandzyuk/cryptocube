#ifndef __gap_detector_h__
#define __gap_detector_h__

#include "otp_package.h"
#include "enque_buffer_sender.h"
#include "file.h"
#include "mutex.h"
#include "timer.h"
#include "task.h"
#include "useful.h"
#include <set>

#include <memory>

#define CONNECTION_GAP_TASKNAME     "cgtask"
#define PAGE_GAP_TASKNAME           "pgtask"
#define SEQUENCE_GAP_TASKNAME       "sgtask"

class GapDetector;
class NotificationsMgrBase;

/******************************************************************/
/*  Task starts deciphering after the first package with AES keys received
    or raises exception after the given timeout */
class ConnectionGapTask : public Task
{
    friend class GapDetector;

public:
    ConnectionGapTask( Communicator* otpComm,
                       NotificationsMgrBase* notifyMgr ); 
    virtual ~ConnectionGapTask();

protected:
    virtual void run( void );

private:
    Communicator* otpComm_;
    NotificationsMgrBase* notifyMgr_;
};

/******************************************************************/
/*  Task continues the OTP deciphering or raises exception 
    after the sequence gap during the time expiration 
    of gap-compensation package waiting */

class SequenceGapTask : public Task
{
    friend class GapDetector;

public:
    SequenceGapTask( u64 clusterId, OTP_Processor* theOwner ); 
    virtual ~SequenceGapTask();

protected:
    virtual void run( void );

private:
    u64 clusterId_;
    OTP_Processor* theOwner;
};

/******************************************************************/
/*  Task to launch the pages sending after the given timeout */
class PageGapTask : public Task
{
    friend class GapDetector;

public:
    PageGapTask( u64 clusterId, OTP_Processor* theOwner ); 
    virtual ~PageGapTask();

protected:
    virtual void run( void );

private:
    u64 clusterId_;
    OTP_Processor* theOwner;
};

/*********************************************************************/
/*  GapDetector will be used for definition are we ready to send data in socket 
    considering the traffic intensity. 
    For example we can send data in cluster using full 4096 bytes,
    during normal or high traffic intensity. Or can send data in chunk including
    one or two or three etc. small packages in case when we have some time gap between 
    AES packages aproximately 50 and more milliseconds. 
    The group of clusters or one cluster or chunk of cluster that directs to socket 
    from outgoing queue is named as "Page".
    GapDetector launches PagesGapTask what send data immediately from outgoing queue 
    after the waiting a some time period (configurable).

    For incoming messages the detector launches SequenceGapTask in case when we receives 
    some amount of clusters with different sequences numbers from different channels.
    E.g. we have received cluster with sequence 127, and after cluster with 129. 
    So we should wait a some time to obtain cluster 128 while incoming clusters pushing in queue.
    After the waiting is expired and no cluster recevied, we raises exception (in current implementation).
    Behaviour is marked as "need improve" and may be solved by some controlling 
    messages between CryptoBoxes.
*/
class GapDetector : private Timer, public Communicator
{
    class sequenceLess {
    public:
        bool operator()( const Cluster& left, 
                         const Cluster& right ) const
        {
            return ( left.getId() < right.getId() );
        }
    };

    typedef std::set<Cluster, sequenceLess> SeqQueueT;

public:
    GapDetector();
    virtual ~GapDetector();

    bool sequencesCtrl( const Cluster& in, ClustersT* out, u16 headPosition );

protected:
    /*  Implementation should catches all exceptions and reports about
        @returns number of processed bytes, this number used to queue clearing
    */
    virtual u32 do_perform(const RawMessage& /*msg*/, SenderType /*type*/);

    /*  Implementation should provides the retreiving own sender type */
    virtual SenderType get_type( void ) 
    { return Communicator::OTP_Module; }

private:
    Mutex cgtLock_;
    std::auto_ptr<ConnectionGapTask> ConnectionGapTask_running;
    SeqQueueT  seqQueue_;
    Markers64T seqGaps_;
    u32 gapBufferSize_;
};

/**/
#endif /* __otp_base_h__ */
