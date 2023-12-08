cmake_minimum_required(VERSION 3.14.1)

project (dcf)

set(DCF_LIBRARY "${PROJECT_SOURCE_DIR}/library")
set(SECUREC_LIB_PATH "${DCF_LIBRARY}/huawei_security/lib")
set(Z4_LIB_PATH "${DCF_LIBRARY}/lz4/lib")
set(ZSTD_LIB_PATH "${DCF_LIBRARY}/zstd/lib")
set(OPENSSL_LIB_PATH "${DCF_LIBRARY}/openssl/lib")
set(CJSON_PATH "${DCF_LIBRARY}/cJSON/lib")
set(VERSION_SRC ${PROJECT_SOURCE_DIR}/src/dcf_version.c)

set(vpp_libsecurec "securec")

set(CMAKE_INSTALL_PREFIX $ENV{dcf_install_prefix})

if (UNIX)
    include(
		"${PROJECT_SOURCE_DIR}/build/cmake_include/CMakeListsInclude.txt"
	)
    message(STATUS "BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
         OR ${CMAKE_BUILD_TYPE} STREQUAL "")
        message(STATUS "CMAKE_BUILD_TYPE is Debug")
        set(CMAKE_BUILD_TYPE Debug)
        Add_Definitions(-DDB_DEBUG_VERSION)
    elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
        message(STATUS "CMAKE_BUILD_TYPE is Release")
        set(CMAKE_BUILD_TYPE Release)
        set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
    else ()
        message(FATAL_ERROR "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
    endif ()

    set(3rd_liblz4 "lz4")
    set(3rd_libzstd "zstd")
    set(3rd_libssl "ssl")
    set(3rd_libjson "cjson")
    set(3rd_lib_crypto "crypto")
	
    set_property(TARGET PROPERTY C_STANDARD 99)

    add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions -lpthread)
    add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT)
    add_link_options(-pie)
    add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
    add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)

    set(CMAKE_SKIP_RPATH TRUE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ldl -pthread -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
    add_compile_options(-fno-common)
    add_compile_options(-Wtrampolines)
    add_compile_options(-freg-struct-return)
    add_compile_options(-pipe)
    add_compile_options(-Wl,-Bsymbolic)
    add_compile_options(-rdynamic)

    OPTION(ENABLE_GCOV "Enable gcov (debug, Linux builds only)" OFF)
    message(STATUS "ENABLE_GCOV = ${ENABLE_GCOV}")
    IF (ENABLE_GCOV AND NOT WIN32 AND NOT APPLE)
        message(STATUS "Enable gcov (debug, Linux builds only).")
        SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fprofile-arcs -ftest-coverage")
        SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fprofile-arcs -ftest-coverage")
        SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fprofile-arcs -ftest-coverage -lgcov")
        set(CMAKE_C_FLAGS "-std=gnu99 ${CMAKE_C_FLAGS}")
    ENDIF()

    OPTION(ENABLE_EXPORT_API "Enable hidden internal api" OFF)
    message(STATUS "ENABLE_EXPORT_API = ${ENABLE_EXPORT_API}")
    IF (ENABLE_EXPORT_API)
        message(STATUS "Enable only dcf_interface.h file's api to external systems.")
        add_compile_options(-fvisibility=hidden)
    ENDIF()

    execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE OS_ARCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})
    if (OS_ARCH STREQUAL "aarch64")
        option(USE_H1620 OFF)
        if (USE_H1620)
            add_compile_options(-march=armv8-a+crc+lse)
            message(STATUS "Toolchain: Build aarch64 USE_H1620")
        else ()
            add_compile_options(-march=armv8-a+crc)
        endif (USE_H1620)

        add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
    elseif (OS_ARCH STREQUAL "x86_64")
        add_compile_options(-msse4.2 )
    endif ()
    Add_Definitions(-DWSEC_COMPILE_CAC_OPENSSL -DWSEC_AES_GCM_SUPPORT -DWSEC_USE_OPENSSL_110)
else ()
    set(3rd_liblz4 "liblz4_static")
    set(3rd_libzstd "libzstd_static")
    set(3rd_libssl "libssl")
    set(3rd_lib_crypto "libcrypto")
    set(3rd_libjson "libcjson")
    set(stack_rlimit 4194304)
    Add_Definitions(-DWIN32_STACK_RLIMIT=${stack_rlimit} -DWIN32 -D_CRT_SECURE_NO_WARNINGS -DDB_DEBUG_VERSION -DWSEC_COMPILE_CAC_OPENSSL -DWSEC_AES_GCM_SUPPORT -DWSEC_USE_OPENSSL_110)

endif ()
add_subdirectory(src)
OPTION(TEST "option for test module" ON)
if (TEST)
    add_subdirectory(test)
endif()