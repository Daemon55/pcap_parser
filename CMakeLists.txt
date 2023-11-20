cmake_minimum_required(VERSION 3.15)
project(bifit-test VERSION 0.1)
set (CMAKE_CXX_STANDARD 23)

add_executable(main main.cpp pcap.cpp)
target_link_libraries(main
                -lpcap)
