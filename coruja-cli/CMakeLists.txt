cmake_minimum_required(VERSION 3.18)
project(coruja-cli
	VERSION 0.0.1
	DESCRIPTION "Coruja core library"
	LANGUAGES C
)
add_executable(${PROJECT_NAME}
	"${PROJECT_SOURCE_DIR}/src/main.c"
)
target_compile_options(${PROJECT_NAME} PRIVATE "-std=c11")
target_include_directories(${PROJECT_NAME}
	PRIVATE
		"${PROJECT_SOURCE_DIR}/src"
		"${PROJECT_SOURCE_DIR}/src/include"
)
# CONAN_PKG::sqlite3
target_link_libraries(${PROJECT_NAME} CONAN_PKG::openssl coruja-core)
