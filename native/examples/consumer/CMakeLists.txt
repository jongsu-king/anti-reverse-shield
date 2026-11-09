# How an application uses the SDK from a release (also run by the release workflow):
#   cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/anti-reverse-shield-sdk
cmake_minimum_required(VERSION 3.15)
project(ars_consumer C)
find_package(ars_shield 0.3 REQUIRED)
add_executable(ars_consumer ../demo.c)
target_link_libraries(ars_consumer PRIVATE ars::shield)
