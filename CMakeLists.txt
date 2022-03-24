cmake_minimum_required(VERSION 3.20)
project(omemo_test)

set(CMAKE_CXX_STANDARD 20)

if(WIN32) # Install dlls in the same directory as the executable on Windows
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

include(FetchContent)
set(BUILD_TESTING OFF)
FetchContent_Declare(libomemo GIT_REPOSITORY https://github.com/UWPX/libomemo-c
                              GIT_TAG omemo)
FetchContent_MakeAvailable(libomemo)
include_directories(${libomemo_SOURCE_DIR}/src)
include_directories(${libomemo_SOURCE_DIR}/tests)

add_executable(omemo_test main.cpp my_test_common.hpp my_test_common.cpp)
target_link_libraries(omemo_test PRIVATE omemo-c)