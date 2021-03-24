cmake_minimum_required(VERSION 3.0.0)
project(SSLClient VERSION 0.1.0)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_PROGRAM}")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z -Wall")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(inc)

add_executable(SSLClient src/main.cpp 
                src/client.cpp )


target_link_libraries(SSLClient ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES} )

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
