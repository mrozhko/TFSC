#ifndef _GLOBAL_H
#define _GLOBAL_H
#include <string>

namespace global{

    enum class BuildType
    {
        kBuildType_Primary,
        kBuildType_Test,
        kBuildType_Dev
    };
    
    // data
    #ifdef PRIMARYCHAIN
        const BuildType kBuildType = BuildType::kBuildType_Primary;
    #elif TESTCHAIN
        const BuildType kBuildType = BuildType::kBuildType_Test;
    #else // DEVCHAIN
        static const BuildType kBuildType = BuildType::kBuildType_Dev;
    #endif

    // version
    static const std::string kNetVersion = "20";
    static const std::string kLinuxCompatible = "0.20.1";
    static const std::string kWindowsCompatible = "0.20.1";
    static const std::string kIOSCompatible = "4.0.4";
    static const std::string kAndroidCompatible = "3.1.0";

    #if WINDOWS
        static const std::string kSystem = "2";
        static const std::string kCompatibleVersion = kWindowsCompatible;
    #else
        static const std::string kSystem = "1";
        static const std::string kCompatibleVersion = kLinuxCompatible;
    #endif 

    #ifdef PRIMARYCHAIN
        static const std::string kVersion = kSystem + "_" + kCompatibleVersion + "_p";
    #elif TESTCHAIN
        static const std::string kVersion = kSystem + "_" + kCompatibleVersion + "_t";
    #else // DEVCHAIN
        static const std::string kVersion = kSystem + "_" + kCompatibleVersion + "_d";
    #endif

}

#endif // !_GLOBAL_H
