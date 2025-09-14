# Copyright (c) 2025 Rhett Creighton
set(CLI_INCLUDES
	"${libgit3_BINARY_DIR}/src/util"
	"${libgit3_BINARY_DIR}/include"
	"${libgit3_SOURCE_DIR}/src/util"
	"${libgit3_SOURCE_DIR}/src/cli"
	"${libgit3_SOURCE_DIR}/include"
	"${LIBGIT3_DEPENDENCY_INCLUDES}"
	"${LIBGIT3_SYSTEM_INCLUDES}")

if(WIN32 AND NOT CYGWIN)
	file(GLOB CLI_SRC_OS win32/*.c)
	list(SORT CLI_SRC_OS)
else()
	file(GLOB CLI_SRC_OS unix/*.c)
	list(SORT CLI_SRC_OS)
endif()

file(GLOB CLI_SRC_C *.c *.h)
list(SORT CLI_SRC_C)

#
# The CLI currently needs to be statically linked against libgit3 because
# the utility library uses libgit3's thread-local error buffers.  TODO:
# remove this dependency and allow us to dynamically link against libgit3.
#

if(BUILD_CLI STREQUAL "dynamic")
	set(CLI_LIBGIT3_LIBRARY libgit3package)
else()
	set(CLI_LIBGIT3_OBJECTS $<TARGET_OBJECTS:libgit3>)
endif()

#
# Compile and link the CLI
#

add_executable(git3_cli ${CLI_SRC_C} ${CLI_SRC_OS} ${CLI_OBJECTS}
	$<TARGET_OBJECTS:util>
	${CLI_LIBGIT3_OBJECTS}
	${LIBGIT3_DEPENDENCY_OBJECTS})
target_link_libraries(git3_cli ${CLI_LIBGIT3_LIBRARY} ${LIBGIT3_SYSTEM_LIBS})

set_target_properties(git3_cli PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${libgit3_BINARY_DIR})
set_target_properties(git3_cli PROPERTIES OUTPUT_NAME ${LIBGIT3_FILENAME})

ide_split_sources(git3_cli)

target_include_directories(git3_cli PRIVATE ${CLI_INCLUDES})

if(MSVC_IDE)
	# Precompiled headers
	set_target_properties(git3_cli PROPERTIES COMPILE_FLAGS "/Yuprecompiled.h /FIprecompiled.h")
	set_source_files_properties(win32/precompiled.c COMPILE_FLAGS "/Ycprecompiled.h")
endif()

install(TARGETS git3_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
