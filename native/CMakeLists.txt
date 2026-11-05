cmake_minimum_required(VERSION 3.15)
project(anti_reverse_shield_native C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_library(ars_shield STATIC
    src/antidebug.c
    src/frida_detect.c
    src/antihook.c
    src/timing.c
    src/react.c
    src/integrity.c
    src/memhash.c)
target_include_directories(ars_shield PUBLIC include)

if(UNIX AND NOT APPLE)
    target_link_libraries(ars_shield PUBLIC ${CMAKE_DL_LIBS})  # dlsym/dl_iterate_phdr
endif()
if(APPLE)
    target_link_libraries(ars_shield PUBLIC ${CMAKE_DL_LIBS})
endif()

add_executable(ars_demo examples/demo.c)
target_link_libraries(ars_demo PRIVATE ars_shield)

if(NOT MSVC)
    target_compile_options(ars_shield PRIVATE -fvisibility=hidden -O2)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(ars_demo PRIVATE -s)
    endif()
endif()
