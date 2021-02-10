cmake_minimum_required(VERSION 3.18)
project(coruja-workspace
	VERSION 0.0.1
	DESCRIPTION "Coruja workspace"
	LANGUAGES C
)

###############
# Conan Setup #
###############

include("${CMAKE_BINARY_DIR}/conanbuildinfo.cmake")
conan_basic_setup(TARGETS)

#####################
# Coruja Submodules #
#####################

add_subdirectory(coruja)
add_subdirectory(coruja-cli)
