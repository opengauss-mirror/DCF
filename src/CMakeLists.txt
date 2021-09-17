add_subdirectory(common)
add_subdirectory(callback)
add_subdirectory(metadata)
add_subdirectory(election)
add_subdirectory(replication)
add_subdirectory(storage)
add_subdirectory(network)
add_subdirectory(utils)

if (WIN32)
add_library(dcf STATIC dcf_interface.c dcf_version.c ${PROJECT_SOURCE_DIR}/src/interface/dcf_interface.h)
target_link_libraries(dcf PRIVATE ${vpp_libsecurec} ${3rd_liblz4} ${3rd_libzstd} ${3rd_libssl} ${3rd_lib_crypto} ${3rd_libjson} Crypt32 common utils
callback metadata election network replication storage)
else ()
MESSAGE(STATUS ${DD_DCF_LIB_VERSION})
MESSAGE(STATUS ${DD_GETLIBVERSION})
add_compile_definitions(DCF_LIB_VERSION=${DD_DCF_LIB_VERSION})
add_compile_definitions(GETLIBVERSION=${DD_GETLIBVERSION})
add_compile_options(-std=gnu99)
add_library(dcf SHARED dcf_interface.c ${VERSION_SRC})
target_link_libraries(dcf PRIVATE ${vpp_libsecurec} ${3rd_liblz4} ${3rd_libzstd} ${3rd_libssl} ${3rd_lib_crypto} ${3rd_libjson} common
utils callback metadata election network replication storage pthread m rt)
endif ()

target_include_directories(dcf PUBLIC
		${PROJECT_SOURCE_DIR}/src/interface
		${PROJECT_SOURCE_DIR}/build/include
		${PROJECT_SOURCE_DIR}/library/huawei_security/include
		${PROJECT_SOURCE_DIR}/library/lz4/include
		${PROJECT_SOURCE_DIR}/library/zstd/include
		${PROJECT_SOURCE_DIR}/library/openssl/include
		${PROJECT_SOURCE_DIR}/library/cJSON/include
		${PROJECT_SOURCE_DIR}/src/common
		${PROJECT_SOURCE_DIR}/src/common/cm_concurrency
		${PROJECT_SOURCE_DIR}/src/common/cm_defines
		${PROJECT_SOURCE_DIR}/src/common/cm_network
		${PROJECT_SOURCE_DIR}/src/common/cm_struct
		${PROJECT_SOURCE_DIR}/src/common/cm_time
		${PROJECT_SOURCE_DIR}/src/common/cm_types
		${PROJECT_SOURCE_DIR}/src/common/cm_utils
		${PROJECT_SOURCE_DIR}/src/common/cm_security
		${PROJECT_SOURCE_DIR}/src/utils
		${PROJECT_SOURCE_DIR}/src/callback
		${PROJECT_SOURCE_DIR}/src/metadata
		${PROJECT_SOURCE_DIR}/src/network
		${PROJECT_SOURCE_DIR}/src/storage
		${PROJECT_SOURCE_DIR}/src/election
		${PROJECT_SOURCE_DIR}/src/replication
)
target_link_directories(dcf PRIVATE ${SECUREC_LIB_PATH} ${Z4_LIB_PATH} ${ZSTD_LIB_PATH} ${OPENSSL_LIB_PATH} ${CJSON_PATH})

set_target_properties(dcf
	PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/lib
    LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/lib
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/bin
)
