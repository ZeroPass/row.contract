include(ExternalProject)

option(ROW_RSA_ENABLED "Add support for RSA signature verification" ON)
option(ROW_BUILD_TEST_ACTIONS "Build test actions" OFF)


# if no cdt root is given use default path
if(EOSIO_CDT_ROOT STREQUAL "" OR NOT EOSIO_CDT_ROOT)
   find_package(eosio.cdt)
endif()

ExternalProject_Add(
   row_project
   SOURCE_DIR ${CMAKE_SOURCE_DIR}/src
   BINARY_DIR ${CMAKE_BINARY_DIR}/row
   CMAKE_ARGS
      -DROW_RSA_ENABLED="${ROW_RSA_ENABLED}"
      -DROW_BUILD_TEST_ACTIONS="${ROW_BUILD_TEST_ACTIONS}"
      -DCMAKE_TOOLCHAIN_FILE="${EOSIO_CDT_ROOT}/lib/cmake/eosio.cdt/EosioWasmToolchain.cmake"
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
)