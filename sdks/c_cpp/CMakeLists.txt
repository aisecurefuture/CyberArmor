cmake_minimum_required(VERSION 3.15)

project(cyberarmor
    VERSION      2.0.0
    DESCRIPTION  "CyberArmor AI Identity Control Plane C/C++ SDK"
    HOMEPAGE_URL "https://cyberarmor.ai"
    LANGUAGES    C CXX
)

# ============================================================================
# Build options
# ============================================================================
option(CA_BUILD_TESTS    "Build unit tests"                  ON)
option(CA_BUILD_EXAMPLES "Build example programs"            ON)
option(CA_INSTALL        "Generate install targets"          ON)
option(CA_BUILD_STATIC   "Build a static library as well"   OFF)

# ============================================================================
# C/C++ standards
# ============================================================================
set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# Find dependencies
# ============================================================================
find_package(CURL REQUIRED)

# ============================================================================
# Source files
# ============================================================================
set(CA_SOURCES
    src/cyberarmor.c
)

set(CA_PUBLIC_HEADERS
    include/cyberarmor/cyberarmor.h
)

# ============================================================================
# Shared library target
# ============================================================================
add_library(cyberarmor SHARED ${CA_SOURCES})

set_target_properties(cyberarmor PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${CA_PUBLIC_HEADERS}"
)

target_include_directories(cyberarmor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(cyberarmor
    PUBLIC CURL::libcurl
)

# Compile definitions
target_compile_definitions(cyberarmor
    PRIVATE CYBERARMOR_BUILDING_DLL
)

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(cyberarmor PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -fvisibility=hidden
    )
elseif(MSVC)
    target_compile_options(cyberarmor PRIVATE
        /W4
        /wd4100  # unreferenced formal parameter
    )
    target_compile_definitions(cyberarmor PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# ============================================================================
# Optional static library
# ============================================================================
if(CA_BUILD_STATIC)
    add_library(cyberarmor_static STATIC ${CA_SOURCES})
    set_target_properties(cyberarmor_static PROPERTIES
        OUTPUT_NAME cyberarmor_static
        PUBLIC_HEADER "${CA_PUBLIC_HEADERS}"
    )
    target_include_directories(cyberarmor_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(cyberarmor_static
        PUBLIC CURL::libcurl
    )
    target_compile_definitions(cyberarmor_static
        PUBLIC CYBERARMOR_STATIC
    )
endif()

# ============================================================================
# Tests
# ============================================================================
if(CA_BUILD_TESTS)
    enable_testing()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_client.c")
        add_executable(cyberarmor_test
            tests/test_client.c
        )
        target_link_libraries(cyberarmor_test PRIVATE cyberarmor)
        target_include_directories(cyberarmor_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        add_test(NAME cyberarmor_unit_test
            COMMAND cyberarmor_test
        )
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_client.cpp")
        add_executable(cyberarmor_cxx_test
            tests/test_client.cpp
        )
        target_link_libraries(cyberarmor_cxx_test PRIVATE cyberarmor)
        target_include_directories(cyberarmor_cxx_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        add_test(NAME cyberarmor_cxx_unit_test
            COMMAND cyberarmor_cxx_test
        )
    endif()
endif()

# ============================================================================
# Examples
# ============================================================================
if(CA_BUILD_EXAMPLES)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/basic_check.c")
        add_executable(example_basic_check examples/basic_check.c)
        target_link_libraries(example_basic_check PRIVATE cyberarmor)
        target_include_directories(example_basic_check PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/basic_check.cpp")
        add_executable(example_basic_check_cxx examples/basic_check.cpp)
        target_link_libraries(example_basic_check_cxx PRIVATE cyberarmor)
        target_include_directories(example_basic_check_cxx PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
    endif()
endif()

# ============================================================================
# pkg-config file generation
# ============================================================================
set(CA_PC_PREFIX      "${CMAKE_INSTALL_PREFIX}")
set(CA_PC_EXEC_PREFIX "\${prefix}")
set(CA_PC_LIBDIR      "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
set(CA_PC_INCLUDEDIR  "\${prefix}/include")
set(CA_PC_VERSION     "${PROJECT_VERSION}")
set(CA_PC_DESCRIPTION "${PROJECT_DESCRIPTION}")

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cyberarmor.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cyberarmor.pc"
    @ONLY
)

# ============================================================================
# Install rules
# ============================================================================
if(CA_INSTALL)
    include(GNUInstallDirs)

    # Library
    install(TARGETS cyberarmor
        EXPORT  CyberArmorTargets
        LIBRARY       DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE       DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME       DESTINATION "${CMAKE_INSTALL_BINDIR}"
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cyberarmor"
    )

    if(CA_BUILD_STATIC)
        install(TARGETS cyberarmor_static
            ARCHIVE       DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cyberarmor"
        )
    endif()

    # CMake package config files
    install(EXPORT CyberArmorTargets
        FILE      CyberArmorTargets.cmake
        NAMESPACE CyberArmor::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CyberArmor"
    )

    include(CMakePackageConfigHelpers)

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/CyberArmorConfigVersion.cmake"
        VERSION       ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CyberArmorConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/CyberArmorConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CyberArmor"
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/CyberArmorConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/CyberArmorConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CyberArmor"
    )

    # pkg-config
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/cyberarmor.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
    )
endif()

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "=== CyberArmor SDK ${PROJECT_VERSION} ===")
message(STATUS "  Build type     : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C standard     : ${CMAKE_C_STANDARD}")
message(STATUS "  C++ standard   : ${CMAKE_CXX_STANDARD}")
message(STATUS "  CURL version   : ${CURL_VERSION_STRING}")
message(STATUS "  Build tests    : ${CA_BUILD_TESTS}")
message(STATUS "  Build examples : ${CA_BUILD_EXAMPLES}")
message(STATUS "  Build static   : ${CA_BUILD_STATIC}")
message(STATUS "  Install prefix : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
