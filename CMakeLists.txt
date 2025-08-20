cmake_minimum_required(VERSION 3.25) # 3.31
project(app C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(csock)
add_subdirectory(cssl)
add_subdirectory(cthread)
add_subdirectory(cstring)

add_executable(app main.c)

target_link_libraries(app PRIVATE cstring csock cthread cssl)

file(COPY resources DESTINATION ${CMAKE_CURRENT_BINARY_DIR})