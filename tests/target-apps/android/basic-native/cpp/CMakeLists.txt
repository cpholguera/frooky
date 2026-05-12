cmake_minimum_required(VERSION 3.22.1)
project("basic-native")

add_library(receiveFundamentalValue SHARED receiveFundamentalValue.c)
add_library(receiveFundamentalReference SHARED receiveFundamentalReference.c)
add_library(receiveString SHARED receiveString.c)

find_library(log-lib log)
target_link_libraries(receiveFundamentalValue ${log-lib})
target_link_libraries(receiveFundamentalReference ${log-lib})
target_link_libraries(receiveString ${log-lib})
