cmake_minimum_required(VERSION 3.31.6)
project("ndkdemo")

add_library(fundamentalTypes SHARED fundamentalTypes.c)

find_library(log-lib log)
target_link_libraries(fundamentalTypes ${log-lib})