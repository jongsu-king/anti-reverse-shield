cmake_minimum_required(VERSION 3.15)
project(anti_reverse_shield_native VERSION 0.3.0 LANGUAGES C CXX)

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
target_include_directories(ars_shield PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

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

# ---- install / SDK package ------------------------------------------------
# `cmake --install build --prefix <dir>` lays out an SDK:
#   include/shield.h, include/obfstr.hpp, lib/<static library>, bin/ars_demo,
#   lib/cmake/ars_shield/ (find_package(ars_shield) -> target ars::shield)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
set_target_properties(ars_shield PROPERTIES EXPORT_NAME shield)
install(TARGETS ars_shield EXPORT ars_shieldTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS ars_demo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT ars_shieldTargets NAMESPACE ars:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ars_shield)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/ars_shieldConfig.cmake
     "include(CMakeFindDependencyMacro)\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/ars_shieldTargets.cmake\")\n")
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/ars_shieldConfigVersion.cmake
     VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ars_shieldConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/ars_shieldConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ars_shield)
