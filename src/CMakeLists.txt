project(row)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

if(ROW_RSA_ENABLED)
    message("Support for RSA is enabled.")
    add_definitions(-DROW_RSA_ENABLED=1)
endif()

if(ROW_BUILD_TEST_ACTIONS)
    message("Building ROW contract with test actions.")
    add_definitions(-DROW_TEST_ACTIONS_ENABLED=1)
endif()

add_contract( ${CMAKE_PROJECT_NAME} row row.cpp )
target_include_directories( ${CMAKE_PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( ${CMAKE_PROJECT_NAME} ${CMAKE_SOURCE_DIR}/../ricardian )
