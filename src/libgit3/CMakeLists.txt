# Copyright (c) 2025 Rhett Creighton
# libgit3: the shared library: this CMakeLists.txt compiles the core
# git library functionality with SHA3 support.

add_library(libgit3 OBJECT)

include(PkgBuildConfig)
include(CMakePackageConfigHelpers)

set(LIBGIT3_INCLUDES
	"${PROJECT_BINARY_DIR}/src/util"
	"${PROJECT_BINARY_DIR}/include"
	"${PROJECT_SOURCE_DIR}/src/libgit3"
	"${PROJECT_SOURCE_DIR}/src/util"
	"${PROJECT_SOURCE_DIR}/include"
	"${PROJECT_SOURCE_DIR}/deps/xdiff"
	"${PROJECT_SOURCE_DIR}/deps/ntlmclient"
	"${PROJECT_SOURCE_DIR}/deps/llhttp")

# Collect sourcefiles
file(GLOB SRC_H
	"${PROJECT_SOURCE_DIR}/include/git3.h"
	"${PROJECT_SOURCE_DIR}/include/git3/*.h"
	"${PROJECT_SOURCE_DIR}/include/git3/sys/*.h")
list(SORT SRC_H)
target_sources(libgit3 PRIVATE ${SRC_H})

file(GLOB SRC_GIT3 *.c *.h
	streams/*.c streams/*.h
	transports/*.c transports/*.h)
list(SORT SRC_GIT3)
target_sources(libgit3 PRIVATE ${SRC_GIT3})

if(WIN32 AND NOT CYGWIN)
	# Add resource information on Windows
	set(SRC_RC "git3.rc")
endif()

if(APPLE)
	# The old Secure Transport API has been deprecated in macOS 10.15.
	set_source_files_properties(streams/stransport.c PROPERTIES COMPILE_FLAGS -Wno-deprecated)
endif()

ide_split_sources(libgit3)
list(APPEND LIBGIT3_OBJECTS $<TARGET_OBJECTS:util> $<TARGET_OBJECTS:libgit3> ${LIBGIT3_DEPENDENCY_OBJECTS})
list(APPEND LIBGIT3_INCLUDES ${LIBGIT3_DEPENDENCY_INCLUDES})

target_include_directories(libgit3 PRIVATE ${LIBGIT3_INCLUDES} ${LIBGIT3_DEPENDENCY_INCLUDES} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(libgit3 SYSTEM PRIVATE ${LIBGIT3_SYSTEM_INCLUDES})

set(LIBGIT3_INCLUDES ${LIBGIT3_INCLUDES} PARENT_SCOPE)
set(LIBGIT3_OBJECTS ${LIBGIT3_OBJECTS} PARENT_SCOPE)
set(LIBGIT3_DEPENDENCY_INCLUDES ${LIBGIT3_DEPENDENCY_INCLUDES} PARENT_SCOPE)
set(LIBGIT3_DEPENDENCY_OBJECTS ${LIBGIT3_DEPENDENCY_OBJECTS} PARENT_SCOPE)
set(LIBGIT3_SYSTEM_INCLUDES ${LIBGIT3_SYSTEM_INCLUDES} PARENT_SCOPE)
set(LIBGIT3_SYSTEM_LIBS ${LIBGIT3_SYSTEM_LIBS} PARENT_SCOPE)

#
# Compile and link libgit3
#

add_library(libgit3package ${SRC_RC} ${LIBGIT3_OBJECTS})
target_link_libraries(libgit3package ${LIBGIT3_SYSTEM_LIBS})
target_include_directories(libgit3package SYSTEM PRIVATE ${LIBGIT3_INCLUDES})
target_include_directories(libgit3package INTERFACE $<INSTALL_INTERFACE:include>)

set_target_properties(libgit3package PROPERTIES C_STANDARD 90)
set_target_properties(libgit3package PROPERTIES C_EXTENSIONS OFF)
set_target_properties(libgit3package PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(libgit3package PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(libgit3package PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

ide_split_sources(libgit3package)

if(SONAME)
	set_target_properties(libgit3package PROPERTIES VERSION ${PROJECT_VERSION})
	set_target_properties(libgit3package PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")
	if(LIBGIT3_FILENAME)
		target_compile_definitions(libgit3package PRIVATE LIBGIT3_FILENAME=\"${LIBGIT3_FILENAME}\")
		set_target_properties(libgit3package PROPERTIES OUTPUT_NAME ${LIBGIT3_FILENAME})
	elseif(DEFINED LIBGIT3_PREFIX)
		set_target_properties(libgit3package PROPERTIES PREFIX "${LIBGIT3_PREFIX}")
	endif()
endif()

pkg_build_config(NAME "lib${LIBGIT3_FILENAME}"
	VERSION ${PROJECT_VERSION}
	DESCRIPTION "The git3 library with SHA3-256 and proof-of-work"
	LIBS_SELF ${LIBGIT3_FILENAME}
	PRIVATE_LIBS ${LIBGIT3_PC_LIBS}
	REQUIRES ${LIBGIT3_PC_REQUIRES})

if(MSVC_IDE)
	# Precompiled headers
	set_target_properties(libgit3package PROPERTIES COMPILE_FLAGS "/Yuprecompiled.h /FIprecompiled.h")
	set_source_files_properties(win32/precompiled.c COMPILE_FLAGS "/Ycprecompiled.h")
endif()

# support experimental features and functionality

configure_file(experimental.h.in "${PROJECT_BINARY_DIR}/include/git3/experimental.h")

# translate filenames in the git3.h so that they match the install directory
# (allows for side-by-side installs of libgit3 and libgit3-experimental.)

FILE(READ "${PROJECT_SOURCE_DIR}/include/git3.h" LIBGIT3_INCLUDE)
STRING(REGEX REPLACE "#include \"git3\/" "#include \"${LIBGIT3_FILENAME}/" LIBGIT3_INCLUDE "${LIBGIT3_INCLUDE}")
FILE(WRITE "${PROJECT_BINARY_DIR}/include/${LIBGIT3_FILENAME}.h" ${LIBGIT3_INCLUDE})

# cmake package targets

set(LIBGIT3_TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")

write_basic_package_version_file(
	"${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}ConfigVersion.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY SameMajorVersion)

configure_file(config.cmake.in
	"${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}Config.cmake"
	@ONLY)

install(FILES
	"${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}Config.cmake"
	"${PROJECT_BINARY_DIR}/cmake/${PROJECT_NAME}ConfigVersion.cmake"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
install(
	EXPORT ${LIBGIT3_TARGETS_EXPORT_NAME}
	NAMESPACE "${PROJECT_NAME}::"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

# Install

install(TARGETS libgit3package
	EXPORT ${LIBGIT3_TARGETS_EXPORT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/git3/
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBGIT3_FILENAME}")
install(FILES ${PROJECT_BINARY_DIR}/include/git3/experimental.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBGIT3_FILENAME}")
install(FILES "${PROJECT_BINARY_DIR}/include/${LIBGIT3_FILENAME}.h"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
