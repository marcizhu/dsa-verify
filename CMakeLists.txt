cmake_minimum_required(VERSION 3.1)
project(dsa-verify VERSION 0.1.0 LANGUAGES C)

#---------------------------------------------------------------------------------------
# set default build to debug
#---------------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

# ---------------------------------------------------------------------------------------
# Set DSA_VERIFY_MASTER_PROJECT to ON if we are building Units
# ---------------------------------------------------------------------------------------
# Check if Units is being used directly or via add_subdirectory, but allow overriding
if(NOT DEFINED DSA_VERIFY_MASTER_PROJECT)
	if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
		set(DSA_VERIFY_MASTER_PROJECT ON)
		message(STATUS "Building dsa-verify as master project")
	else()
		set(DSA_VERIFY_MASTER_PROJECT OFF)
	endif()
endif()

#---------------------------------------------------------------------------------------
# compiler config
#---------------------------------------------------------------------------------------
option(DSA_VERIFY_BUILD_EXAMPLES "Build example files" ${DSA_VERIFY_MASTER_PROJECT})

message(STATUS "Build type: " ${CMAKE_BUILD_TYPE})

if(DSA_VERIFY_BUILD_EXAMPLES)
	# simple-verify
	add_executable(simple-verify examples/simple_verify.c)
	target_link_libraries(simple-verify dsa-verify)

	# dsa-verify
	add_executable(verify examples/verify_tool.c)
	target_link_libraries(verify dsa-verify)
endif()

add_library(dsa-verify STATIC src/der.c src/dsa_verify.c src/mp_math.c src/sha1.c)
target_include_directories(dsa-verify PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(dsa-verify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
