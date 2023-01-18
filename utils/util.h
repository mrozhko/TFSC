#ifndef _Util_H_
#define _Util_H_

#include <string>
#include <fstream>
#include <map>
#include <vector>
#include <functional>
#include "../utils/string_util.h"

class Util
{
    
public:
    Util();
    ~Util();
    
    static uint32_t adler32(const unsigned char *data, size_t len); 

    /* ====================================================================================  
    # @description:  Determine if the version is compatible
    # @param recvVersion  The version of the received data
    # @return: succeed: 0;
    # 			fail: -1,  The version of the data received is lower than the minimum compatible version
    ==================================================================================== */
   static int IsVersionCompatible( std::string recvVersion );

   static int IsLinuxVersionCompatible(const std::vector<std::string> & vRecvVersion);

   static int IsOtherVersionCompatible(const std::string & vRecvVersion, bool bIsAndroid);
};


#endif