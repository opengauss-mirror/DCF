file(GLOB_RECURSE CURRENT_HEADERS  *.h)
file(GLOB_RECURSE CURRENT_SOURCE  *.c)

source_group("Include" FILES ${CURRENT_HEADERS})

add_library(election OBJECT ${CURRENT_SOURCE} ${CURRENT_HEADERS})

target_include_directories(election PUBLIC
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
        ${PROJECT_SOURCE_DIR}/src/callback
        ${PROJECT_SOURCE_DIR}/src/metadata
        ${PROJECT_SOURCE_DIR}/src/network
        ${PROJECT_SOURCE_DIR}/src/storage
        ${PROJECT_SOURCE_DIR}/src/replication
        ${PROJECT_SOURCE_DIR}/src/utils
)

