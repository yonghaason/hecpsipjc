cmake_minimum_required (VERSION 3.15)

project(volePSI VERSION 0.1.2)

set(VOLEPSI_BUILD ON)

# sets some variables
include(cmake/preamble.cmake)

# sets build option
include(cmake/buildOptions.cmake)

# find all the dependancies.
include(cmake/findDependancies.cmake)

if(VOLE_PSI_ENABLE_SEAL)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/SEAL/CMakeLists.txt")
        message(FATAL_ERROR "SEAL submodule missing; run git submodule update --init thirdparty/SEAL")
    endif()
    set(SEAL_BUILD_DEPS OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)
    set(SEAL_USE_MSGSL OFF CACHE BOOL "" FORCE)
    set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
    set(SEAL_USE_ZSTD OFF CACHE BOOL "" FORCE)
    add_subdirectory(thirdparty/SEAL EXCLUDE_FROM_ALL)
endif()

# build volePSI
add_subdirectory(volePSI)

# build the tests.
add_subdirectory(tests)

# link the executable.
add_subdirectory(frontend)

# setup the install
include(cmake/install.cmake)
