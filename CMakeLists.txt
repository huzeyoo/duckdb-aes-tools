cmake_minimum_required(VERSION 3.10)

set(TARGET_NAME aes_tools)

find_package(OpenSSL REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)

set(
    EXTENSION_SOURCES
    src/aes_tools_extension.cpp
)

build_static_extension(
    ${TARGET_NAME}
    ${EXTENSION_SOURCES}
)

build_loadable_extension(
    ${TARGET_NAME}
    " "
    ${EXTENSION_SOURCES}
)

target_link_libraries(
    ${EXTENSION_NAME}
    OpenSSL::Crypto
)

target_link_libraries(
    ${LOADABLE_EXTENSION_NAME}
    OpenSSL::Crypto
)

install(
    TARGETS ${EXTENSION_NAME}
    EXPORT "${DUCKDB_EXPORT_SET}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
)