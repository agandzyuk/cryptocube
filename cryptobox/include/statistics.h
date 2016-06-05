#ifndef __statistics_h__
#define __statistics_h__

#include "configuration.h"
#include "ethernet_frame.h"
#include "arp_package.h"
#include "ip_package.h"
#include "ip6_package.h"
#include "file.h"

#define IN_TCP_LOGFILE          "./tcp_flow.in"
#define IN_UDP_LOGFILE          "./udp_flow.in"
#define IN_ICMP_LOGFILE         "./icmp_flow.in"
#define IN_IGMP_LOGFILE         "./igmp_flow.in"
#define IN_ARP_LOGFILE          "./arp_flow.in"
#define IN_IP6_LOGFILE          "./ip6_flow.in"
#define IN_UNHANDLED_LOGFILE    "./unhandled_flow.in"

#define OUT_TCP_LOGFILE          "./tcp_flow.out"
#define OUT_UDP_LOGFILE          "./udp_flow.out"
#define OUT_ICMP_LOGFILE         "./icmp_flow.out"
#define OUT_IGMP_LOGFILE         "./igmp_flow.out"
#define OUT_ARP_LOGFILE          "./arp_flow.out"
#define OUT_IP6_LOGFILE          "./ip6_flow.out"
#define OUT_UNHANDLED_LOGFILE    "./unhandled_flow.out"

/*************************************************************************************/
class Statistics
{
public:
    static void print_frame_statistics( u32 sz, FILE* outlog );

    static void print_ethernet_header( const EthernetFrame& msg, FILE* outlog );
    static void print_ip_header( const IPPackage& msg, FILE* outlog, u16* fragment_offset );
    static void print_arp_header( const ARPPackage& msg, FILE* outlog );
    static void print_ip6_header( const IP6Package& msg, FILE* outlog );

    static void print_tcp_packet( const IPPackage& msg, FILE* outlog );
    static void print_udp_packet( const IPPackage& msg, FILE* outlog );
    static void print_icmp_packet( const IPPackage& msg, FILE* outlog );
    static void print_igmp_packet( const IPPackage& msg, FILE* outlog );
    static void print_data( const u8* data, i32 sz, FILE* outlog );
};

/*************************************************************************************/
class StatisticsLogger
{
    friend class Statistics;

public:

    inline bool is_enabled( void ) const
    { return inlog_ ? GV_InNetworkHeadersLogging : GV_OutNetworkHeadersLogging; }

    inline FILE* getTcpLogger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_tcp_.isOpened() )
            in_tcp_.open( IN_TCP_LOGFILE, "w+");
        else if( !inlog_ && !out_tcp_.isOpened() ) {
            out_tcp_.open( OUT_TCP_LOGFILE, "w+");
        }
        return (inlog_ ? in_tcp_.getHandle() : out_tcp_.getHandle());
    }

    inline FILE* getUdpLogger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_udp_.isOpened() )
            in_udp_.open( IN_UDP_LOGFILE, "w+");
        else if( !inlog_ && !out_udp_.isOpened() ) {
            out_udp_.open( OUT_UDP_LOGFILE, "w+");
        }
        return (inlog_ ? in_udp_.getHandle() : out_udp_.getHandle());
    }

    inline FILE* getIcmpLogger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_icmp_.isOpened() )
            in_icmp_.open( IN_ICMP_LOGFILE, "w+");
        else if( !inlog_ && !out_icmp_.isOpened() ) {
            out_icmp_.open( OUT_ICMP_LOGFILE, "w+");
        }
        return (inlog_ ? in_icmp_.getHandle() : out_icmp_.getHandle());
    }

    inline FILE* getIgmpLogger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_igmp_.isOpened() )
            in_igmp_.open( IN_IGMP_LOGFILE, "w+");
        else if( !inlog_ && !out_igmp_.isOpened() ) {
            out_igmp_.open( OUT_IGMP_LOGFILE, "w+");
        }
        return (inlog_ ? in_igmp_.getHandle() : out_igmp_.getHandle());
    }

    inline FILE* getArpLogger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_arp_.isOpened() )
            in_arp_.open( IN_ARP_LOGFILE, "w+");
        else if( !inlog_ && !out_arp_.isOpened() ) {
            out_arp_.open( OUT_ARP_LOGFILE, "w+");
        }
        return (inlog_ ? in_arp_.getHandle() : out_arp_.getHandle());
    }

    inline FILE* getIp6Logger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_ip6_.isOpened() )
            in_ip6_.open( IN_IP6_LOGFILE, "w+");
        else if( !inlog_ && !out_ip6_.isOpened() ) {
            out_ip6_.open( OUT_IP6_LOGFILE, "w+");
        }
        return (inlog_ ? in_ip6_.getHandle() : out_ip6_.getHandle());
    }

    inline FILE* getUnhandledLogger(void) const {
        assert(is_enabled() && "StatisticsLogger: headers logging is disabled!");
        if( inlog_ && !in_unhandled_.isOpened() )
            in_unhandled_.open( IN_UNHANDLED_LOGFILE, "w+");
        else if( !inlog_ && !out_unhandled_.isOpened() ) {
            out_unhandled_.open( OUT_UNHANDLED_LOGFILE, "w+");
        }
        return (inlog_ ? in_unhandled_.getHandle() : out_unhandled_.getHandle());
    }

    StatisticsLogger(bool inlog);
    ~StatisticsLogger();

private:
    static File in_tcp_;
    static File in_udp_;
    static File in_icmp_;
    static File in_igmp_;
    static File in_ip6_;
    static File in_arp_;
    static File in_unhandled_;
    static File out_tcp_;
    static File out_udp_;
    static File out_icmp_;
    static File out_igmp_;
    static File out_ip6_;
    static File out_arp_;
    static File out_unhandled_;
    bool inlog_;
};

#endif /* __statistics_h__ */
