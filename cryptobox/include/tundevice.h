#ifndef __tun_device_h__
#define __tun_device_h__

#include "ipaddress.h"
#include "socket.h"

#define TUN_DEVICE_BUFFER_SIZE 0x10000

/*******************************************************/
/*  This class implements TunTap interface IO.    */
class TunDevice
{
public:
    /*  Create tun interface IO device.
        @tunName Interface name.
        @bufferSize IO buffer size.
        @throw Exception on errors.
    */
    TunDevice(const std::string& tunName, u32 bufferSize = TUN_DEVICE_BUFFER_SIZE);
    ~TunDevice();

    /*  Checks is device opened.
        @return true if device not opened, false otherwise.
    */
    bool is_open( void ) const;

    /*  Returns the IP address of tun interface. */
    IPAddress& getIPAddress( void ) const;

    /*  Transmit a message to another transport end-point. 
        @return the number of bytes that were sent, -1 if an error of EWOULDBLOCK was returned.
        @throw system_exception
    */
    s32 send( const void* msg, s32 len );

    /*  Receives a message from the device.
        @return the number of bytes received, -1 if an error of EWOULDBLOCK was returned.
    */
    s32 recv( void* buf, s32 len );

    /*  Reads the given number of bytes from the device. 
        The purpose of method is to prevent the caller from having to handle a short count.
        @return number of bytes read, -1 on error.
    */
    s32 readN( void* buf, s32 bytes );

    /*  Returns the number of bytes available to read. 
        You should avoid doing this because it is highly inefficient, 
        and it subjects an application to an incorrect data count. 
        @throw system_exception
    */
    s32 availableToRead( void );

    /*  Blocks until the device is ready to read.
        @return true when device to read, false when timeout ends
    */
    bool untilReadyToRead( struct timeval* timeout = NULL );

    /*  Blocks until the device is ready to write.
	    @return true when device to write, false when timeout ends
    */
    bool untilReadyToWrite( struct timeval* timeout = NULL );

    /*  Sets the device in nonblocking mode.    */
    void set_nonblocking( bool on = true );

    /*  Gets the device descriptor */
    inline SD get_fd(void) const
    { return fd_; }

    /*  Gets the device name */
    inline const std::string& get_name(void) const
    { return tunName_; }

private:
    i32 alloc(const std::string& tunName);

    bool is_open_;
    SD fd_;

    mutable IPAddress address_;
    std::string tunName_;
};

/* */
#endif /* __tun_device_h__ */
