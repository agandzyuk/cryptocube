#include "notifications_mgr_base.h"
#include "mainframe.h"

#include <iostream>

using namespace std;

void print_menu()
{
    printf("Crypto Client Usage:\n");
    printf("N - new connection.\n");
    printf("X - stop connection.\n");
    printf("R - restore connection by id.\n");
    printf("S - sending time interval.\n");
    printf("I - reconnecting time interval.\n");
    printf("P - packages size.\n");
    printf("F - file replay for connection (by id).\n");
    printf("M - call menu.\n");
    printf("Q - quit Crypto Client.\n");
}

/*******************************************************/
int main( int /*argc*/, char** /*argv*/ )
{
    print_menu();
    try 
    {
        Mainframe mainframe;
        mainframe.join();
    }
    catch(const Exception& ex)
    {
#ifdef WIN32
        char oembuf[512] = {0};
        CharToOemBuff( ex.reason().c_str(), (LPSTR)oembuf, strlen( ex.reason().c_str() )+1 );
        printf(">> Error: %s\n", oembuf);
#else
        printf(">> Error: %s\n", ex.what());
#endif
    }
    return 0;
}
