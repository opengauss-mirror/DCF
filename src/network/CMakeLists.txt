file(GLOB_RECURSE CURRENT_HEADERS  *.h)
aux_source_directory(./ NETWORK_SRC)
aux_source_directory(./mec NETWORK_MEC_SRC)
aux_source_directory(./protocol NETWORK_PROTOCOL_SRC)
aux_source_directory(./compress NETWORK_COMPRESS_SRC)

set(NETWORK_ALL_SRC
        ${NETWORK_SRC}
        ${NETWORK_MEC_SRC}
        ${NETWORK_PROTOCOL_SRC}
       ${NETWORK_COMPRESS_SRC}
        )
source_group("Include" FILES ${CURRENT_HEADERS})
add_library(network OBJECT ${NETWORK_ALL_SRC} ${CURRENT_HEADERS})

target_include_directories(network PUBLIC
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
        ${PROJECT_SOURCE_DIR}/src/network/protocol
        ${PROJECT_SOURCE_DIR}/src/network/mec
        ${PROJECT_SOURCE_DIR}/src/network/compress
)

OPTION(UT "option for UT" OFF)
if (UT)
list(REMOVE_ITEM NETWORK_ALL_SRC "./mec/mec_func.c")
add_library(network4ut OBJECT ${NETWORK_ALL_SRC})

target_include_directories(network4ut PUBLIC
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
        ${PROJECT_SOURCE_DIR}/src/network/protocol
        ${PROJECT_SOURCE_DIR}/src/network/mec
        ${PROJECT_SOURCE_DIR}/src/network/compress
)
endif ()