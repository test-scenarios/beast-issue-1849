cmake_minimum_required(VERSION 3.15)
project(boost_beast_test)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost 1.71.0 REQUIRED
    COMPONENTS
        filesystem
        system
)

find_package(OpenSSL REQUIRED)

add_executable(boost_beast_test "")
target_sources(boost_beast_test
    PRIVATE
        main.cpp
        http/authorization.hpp
        http/client.cpp
        http/client.hpp
        http/client_transport.hpp
)

target_link_libraries(boost_beast_test
    PRIVATE
        $<$<BOOL:${WIN32}>:ws2_32>
        ${Boost_FILESYSTEM_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
        OpenSSL::SSL OpenSSL::Crypto
)
