project(row_tests)
find_package(eosio.cdt)
add_native_executable(row_test row_test.cpp ${CMAKE_SOURCE_DIR}/../src/row.cpp)
target_include_directories(row_test PUBLIC ${CMAKE_SOURCE_DIR}/../include)
