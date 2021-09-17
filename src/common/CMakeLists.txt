file(GLOB_RECURSE CURRENT_HEADERS  *.h)
aux_source_directory(./ COMMON_SRC)
aux_source_directory(./cm_concurrency CM_CONCURRENCY_SRC)
aux_source_directory(./cm_defines CM_DEFINES_SRC)
aux_source_directory(./cm_network CM_NETWORK_SRC)
aux_source_directory(./cm_struct CM_STRUCT_SRC)
aux_source_directory(./cm_time CM_TIME_SRC)
aux_source_directory(./cm_types CM_TYPE_SRC)
aux_source_directory(./cm_utils CM_UTILS_SRC)
aux_source_directory(./cm_security CM_SECURITY_SRC)
aux_source_directory(./json JSON_SRC)
aux_source_directory(./lexer LEXER_SRC)

set(COMMON_ALL_SRC
        ${COMMON_SRC}
        ${CM_DEFINES_SRC}
        ${CM_CONCURRENCY_SRC}
        ${CM_NETWORK_SRC}
        ${CM_STRUCT_SRC}
        ${CM_TIME_SRC}
        ${CM_TYPE_SRC}
        ${CM_UTILS_SRC}
        ${CM_SECURITY_SRC}
        ${JSON_SRC}
        ${LEXER_SRC}
        )

source_group("Include" FILES ${CURRENT_HEADERS})
add_library(common OBJECT ${COMMON_ALL_SRC} ${CURRENT_HEADERS})

target_include_directories(common PUBLIC
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
        ${PROJECT_SOURCE_DIR}/src/common/json
        ${PROJECT_SOURCE_DIR}/src/common/lexer
        ${PROJECT_SOURCE_DIR}/src/utils
)