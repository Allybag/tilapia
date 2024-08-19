cmake_minimum_required(VERSION 3.22)
project(tilapia)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(src)
add_subdirectory(src)
