cmake_minimum_required(VERSION 3.10)

project(hashsum)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(hashsum HashSum.cpp WindowsHash.cpp)
    target_link_libraries(hashsum bcrypt)
elseif(APPLE)
    add_executable(hashsum HashSum.cpp macOSHash.cpp)
    find_library(SECURITY Security)
    find_library(COREFOUNDATION CoreFoundation)
    target_link_libraries(hashsum ${SECURITY} ${COREFOUNDATION})
else()
    add_executable(hashsum HashSum.cpp)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
    target_link_libraries(hashsum PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
endif()

# Check if the system is Linux
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    # Install the binary to /usr/bin
    install(TARGETS hashsum DESTINATION /usr/bin)

    # Determine the Linux distribution using lsb_release
    execute_process(COMMAND lsb_release -is
                    OUTPUT_VARIABLE LINUX_DISTRIBUTION
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Common CPack configuration
    set(CPACK_PACKAGE_NAME "hashsum")
    set(CPACK_PACKAGE_VERSION "1.0.0")
    set(CPACK_PACKAGE_CONTACT "ChatGPTDev <chatgptdev@tuta.io>")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "HashSum is a tool to calculate the hash of files in a given directory and its subdirectories.")

    if(LINUX_DISTRIBUTION MATCHES "Debian" OR LINUX_DISTRIBUTION MATCHES "Ubuntu")
        # CPack configuration for generating .deb package
        set(CPACK_GENERATOR "DEB")
        set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
        set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl-dev")

        # Set the .deb file name to include the target architecture
        #set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
        set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
    elseif(LINUX_DISTRIBUTION MATCHES "Fedora" OR LINUX_DISTRIBUTION MATCHES "CentOS" OR LINUX_DISTRIBUTION MATCHES "RedHat" OR LINUX_DISTRIBUTION MATCHES "openSUSE")
        # CPack configuration for generating .rpm package
        set(CPACK_GENERATOR "RPM")
        set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
        set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
        set(CPACK_RPM_PACKAGE_REQUIRES "openssl-devel")

        # Set the .rpm file name to include the target architecture
        #set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
        set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    include(CPack)
endif()

# Check if the system is macOS
if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    # Set the macOS target architectures to x64 and arm64 for universal binary
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64")
endif()

# Check if the system is Windows
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    # Use the static C runtime
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
