cmake_minimum_required(VERSION 3.0.2)

set(PATCH_VERSION "1" CACHE STRING "Patch version")

project(ip_filter VERSION 0.0.${PATCH_VERSION})

find_package(GTest)
if (NOT DEFINED GTEST_BOTH_LIBRARIES)
	set(GTEST_BOTH_LIBRARIES gtest gtest_main)
endif()

set(SOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(HEADERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

set(CLI_NAME ${PROJECT_NAME})
set(TEST_NAME ${PROJECT_NAME}-test)

# Build
add_executable(${CLI_NAME} ${SOURCES_DIR}/main.cpp)
add_executable(${TEST_NAME} ${TESTS_DIR}/test.cpp)

# Properties
set_target_properties(${CLI_NAME} ${TEST_NAME}
	PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
)

target_include_directories(${CLI_NAME}
	PRIVATE ${HEADERS_DIR}
)
target_include_directories(${TEST_NAME}
	PRIVATE ${HEADERS_DIR} ${GTEST_INCLUDE_DIRS}
)

target_link_libraries(${TEST_NAME}
	PRIVATE ${GTEST_BOTH_LIBRARIES}
)

if (MSVC)
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

	target_compile_options(${CLI_NAME}
		PRIVATE /W4
	)
	target_compile_options(${TEST_NAME}
		PRIVATE /W4
	)
else ()
	target_compile_options(${CLI_NAME}
		PRIVATE -Wall -Wextra -pedantic -Werror
	)
	target_compile_options(${TEST_NAME}
		PRIVATE -Wall -Wextra -pedantic -Werror
	)
endif()

# Build googletest
if (MSVC)
	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/googletest)
endif()


# Install
include(GNUInstallDirs)

install(TARGETS ${CLI_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Deb package
set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

set(CPACK_PACKAGE_CONTACT example@example.com)

include(CPack)

# Tests
enable_testing()
include(GoogleTest)
gtest_discover_tests(${TEST_NAME})
