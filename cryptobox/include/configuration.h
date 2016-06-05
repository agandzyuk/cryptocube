#ifndef __configuration_h__
#define __configuration_h__

#include "common_types.h"
#include "useful.h"

#include <set>

/******************************************************/
/*  Defines */

#ifndef  CRYPTOBOX_CONFIG_FILE_PATH
#define  CRYPTOBOX_CONFIG_FILE_PATH "./cryptobox.conf"
#endif

#ifndef  GATEWAY_TUN_TYPE
#define  GATEWAY_TUN_TYPE           "tun"
#endif

#ifndef  GATEWAY_TAP_TYPE
#define  GATEWAY_TAP_TYPE           "tap"
#endif

#ifndef  GATEWAY_ETH_PACKET_TYPE
#define  GATEWAY_ETH_PACKET_TYPE    "eth"
#endif

#ifndef  GATEWAY_IP_PACKET_TYPE
#define  GATEWAY_IP_PACKET_TYPE     "ip"
#endif

#ifndef  DEF_CRYPTOBOX_PORT
#define  DEF_CRYPTOBOX_PORT 5401
#endif

#ifndef  DEF_CRYPTOBOX_TUNNEL_PORT1
#define  DEF_CRYPTOBOX_TUNNEL_PORT1 5403
#endif

#ifndef  DEF_CRYPTOBOX_TUNNEL_PORT2
#define  DEF_CRYPTOBOX_TUNNEL_PORT2 5409
#endif

#ifndef  DEF_ROUTER_KEEP_ALIVE_TIMEOUT
#define  DEF_ROUTER_KEEP_ALIVE_TIMEOUT 60   /* seconds */
#endif

#ifndef DEF_SSL_RECONNECTION_INTERVAL
#define DEF_SSL_RECONNECTION_INTERVAL  1000 /* milliseconds */
#endif

#ifndef  ANY_PORT_NUMBER
#define  ANY_PORT_NUMBER 0
#endif

#ifndef  PAGE_PER_ONE_AES_KEY
#define  PAGE_PER_ONE_AES_KEY   204800  /* 200K bytes on one AES key */
#endif

#ifndef  AES_PACKAGE_AVGSIZE
#define  AES_PACKAGE_AVGSIZE    0       /* 0 default */
#endif

#ifndef STATISTICS_VIEWER_REFRESH_RATE
#define STATISTICS_VIEWER_REFRESH_RATE 500
#endif

#ifndef IN_NETWORK_HEADERS_LOGGING
#ifndef _DEBUG
#define IN_NETWORK_HEADERS_LOGGING true
#else
#define IN_NETWORK_HEADERS_LOGGING true
#endif
#endif

#ifndef OUT_NETWORK_HEADERS_LOGGING
#ifndef _DEBUG
#define OUT_NETWORK_HEADERS_LOGGING true
#else
#define OUT_NETWORK_HEADERS_LOGGING true
#endif
#endif

#ifndef NETWORK_DATA_LOGGING
#ifndef _DEBUG
#define NETWORK_DATA_LOGGING false
#else
#define NETWORK_DATA_LOGGING false
#endif
#endif

#ifndef OTP_LOGGING
#ifndef _DEBUG
#define OTP_LOGGING false
#else
#define OTP_LOGGING false
#endif
#endif

#ifndef AES_LOGGING
#ifndef _DEBUG
#define AES_LOGGING false
#else
#define AES_LOGGING false
#endif
#endif

/******************************************************/
/*  Global variables */

/*  Gateway configuration */
typedef enum GatewayType {
    GatewayTun      = 0,
    GatewayTap      = 1,
    GatewayEthernet = 2,
    GatewayPacketIP = 3,
}GatewayType;
extern GatewayType GV_GatewayInterfaceType;

extern std::string GV_GatewayInterfaceName;
extern std::string GV_GatewayInterfaceHW;
extern std::string GV_GatewayInterfaceIP;

extern std::string GV_FileSourcePath;
extern std::string GV_FileDestinationPath;

extern u32  GV_GatewayInBufferSize;
extern u32  GV_GatewayOutBufferSize;
extern u32  GV_PackagePerKeySize;
extern u32  GV_PackagePerSocketBufferSize;

extern bool GV_ProxyServer;
extern std::string GV_ProxyIP;
extern u16  GV_ProxyPort;

/*   not supplied under WIN32 (always false) */
extern bool GV_GatewayEnabled;

/* SSL channels configuration */
extern std::string GV_ChannelEth1;
extern std::string GV_ChannelEth2;
extern std::string GV_RemoteIP;
extern std::string GV_CACertificate;
extern std::string GV_SSLPrivateKey;
extern std::string GV_SSLPassword;
extern std::string GV_SSLVerifyPath;
extern std::string GV_SSLVerifyMode;
extern u16 GV_SSLServerPort;
extern u16 GV_SSLRemotePort;
extern u32 GV_SSLReconnectionInterval;
extern u32 GV_TunnelInBufferSize;
extern u32 GV_TunnelOutBufferSize;

/* AES configuration */
extern u32 GV_AesInBufferSize;
extern u32 GV_AesOutBufferSize;
extern u32 GV_AesInKeyStorageSize;
extern u32 GV_AesOutKeyStorageSize;
extern u32 GV_AesBacklogKeyLimit;
extern i32 GV_AesPresendKeysNum;
extern std::string GV_AesFirstKeyPassword;

/* OTP configuration */
extern u32 GV_OtpInBufferSize;
extern u32 GV_OtpOutBufferSize;
extern u32 GV_OtpSeqGapBufferSize;
extern u32 GV_OtpImageCacheSize;
extern u32 GV_OtpPageDeliveryTimelimit;
extern u32 GV_OtpSequenceGapExpirationTimelimit;
extern std::string GV_OtpImagePath;

/*  Logging configuration */
extern bool GV_InNetworkHeadersLogging;
extern bool GV_OutNetworkHeadersLogging;
extern bool GV_NetworkDataLogging;
extern bool GV_OTPInLogging;
extern bool GV_OTPOutLogging;
extern bool GV_AESInLogging;
extern bool GV_AESOutLogging;
extern u32  GV_StatisticsViewerRefreshRate;

/******************************************************/
class File;
typedef std::set<std::string> ParamsT;

class Configuration
{
public:
    /*  Read parameters from profile or create profile configuration 
        file with default data if it not exists (hard-coded default parameters) 
    */
    static void Init();

    /*  Saves current configuration in file 
        Note: config can't be changed during the CryptoBox running, 
        but we will use Terminal for the interactive calibration for some values which does effect on performance.
    */
    static void SaveCurrent();

private:
    static void readConfig( File* pFile );
    static void saveConfig( File* pFile );

    static StringsT getParamFromLine(const std::string& line);
    /*  Returns true if this line is comment */
    static bool eraseComment(std::string* line);

    static ParamsT params_;
};

/**/

#endif /* __configuration_h__ */


