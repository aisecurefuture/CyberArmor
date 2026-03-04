cmake_minimum_required(VERSION 3.16)
project(aishields_rasp C)

set(CMAKE_C_STANDARD 11)

add_library(aishields_rasp SHARED src/aishields_rasp.c)
target_include_directories(aishields_rasp PUBLIC include)
target_link_libraries(aishields_rasp PRIVATE dl pthread)

# Install
install(TARGETS aishields_rasp LIBRARY DESTINATION lib)
install(FILES include/aishields_rasp.h DESTINATION include)
