cmake_minimum_required(VERSION 3.22.1)
project("ndkdemo")

add_library(primitives SHARED primitives.c)

find_library(log-lib log)
target_link_libraries(primitives ${log-lib})