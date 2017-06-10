cmake_minimum_required(VERSION 2.8)
project(ftplibpp)

include_directories(".")

set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions -std=c++11 -O3 -pedantic -march=native -Wall -Wextra -Wno-unused-parameter")
set(SRC_LIST ftplibpp.cpp)

add_library(${PROJECT_NAME} SHARED ${SRC_LIST})

install(FILES libscnet.so DESTINATION /usr/lib/)
install(FILES ftplibpp.h DESTINATION /usr/include/ftplibpp/)
