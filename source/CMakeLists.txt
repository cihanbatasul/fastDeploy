cmake_minimum_required(VERSION 3.2)
project(fastDeploy)
add_executable(deployExe main.c)

find_package(LibSSH REQUIRED)
target_link_libraries(deployExe PRIVATE ssh)
