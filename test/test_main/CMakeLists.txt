include_directories(
${PROJECT_SOURCE_DIR}/src/interface
)

add_executable(test_main test_main.c)
set_target_properties(test_main PROPERTIES LINKER_LANGUAGE "C")

target_link_directories(test_main PRIVATE ${SECUREC_LIB_PATH} ${Z4_LIB_PATH} ${ZSTD_LIB_PATH} ${OPENSSL_LIB_PATH} ${CJSON_PATH})
target_link_libraries(test_main PRIVATE dcf ${vpp_libsecurec} ${3rd_liblz4} ${3rd_libzstd} ${3rd_libssl} ${3rd_lib_crypto} ${3rd_libjson})