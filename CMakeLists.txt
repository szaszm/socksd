cmake_minimum_required(VERSION 3.20)
project(socksd VERSION 0.2 LANGUAGES C)

add_executable(socksd src/main.c src/Logger.c src/Client.c)
target_include_directories(socksd PRIVATE src)
