cmake_minimum_required(VERSION 3.12)
project(program)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

add_subdirectory("src")
add_executable(program main.c)

target_include_directories(program PUBLIC include)
target_link_libraries(program SRC)