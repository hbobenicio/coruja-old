cmake_minimum_required(VERSION 3.18)
project(coruja-core
	VERSION 0.0.1
	DESCRIPTION "Coruja core library"
	LANGUAGES C
)

#######################
# Coruja Core Library #
#######################
add_library(${PROJECT_NAME} STATIC
	"${PROJECT_SOURCE_DIR}/src/coruja/coruja.c"
	"${PROJECT_SOURCE_DIR}/src/coruja/log.c"
	"${PROJECT_SOURCE_DIR}/src/coruja/address.c"
)
target_compile_options(${PROJECT_NAME} PRIVATE "-std=c11")
target_include_directories(${PROJECT_NAME}
	PUBLIC
		"${PROJECT_SOURCE_DIR}/include"
	PRIVATE
		"${PROJECT_SOURCE_DIR}/src"
)

##########################
# Coruja Core Unit Tests #
##########################
add_executable(${PROJECT_NAME}-unit-tests
	"${PROJECT_SOURCE_DIR}/src/coruja/coruja.test.c"
)
target_compile_options(${PROJECT_NAME}-unit-tests PRIVATE "-std=c11")
target_include_directories(${PROJECT_NAME}-unit-tests
	PRIVATE
		"${PROJECT_SOURCE_DIR}/src"
		"${PROJECT_SOURCE_DIR}/include"
)
# CONAN_PKG::sqlite3
target_link_libraries(${PROJECT_NAME}-unit-tests CONAN_PKG::openssl ${PROJECT_NAME})
