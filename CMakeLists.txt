cmake_minimum_required(VERSION 3.10)

project(hashSum)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(hashSum HashSum.cpp)

if(WIN32)
    target_link_libraries(hashSum bcrypt)
else()
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
    target_link_libraries(hashSum PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
endif()

# Check if the system is Linux
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    # Install the binary to /usr/bin
    install(TARGETS hashSum DESTINATION /usr/bin)

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
