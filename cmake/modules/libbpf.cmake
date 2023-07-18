#
# libbpf
#
option(USE_BUNDLED_LIBBPF "Enable building of the bundled libbpf" ${USE_BUNDLED_DEPS})

if(LIBBPF_INCLUDE)
    # we already have libbpf
elseif(NOT USE_BUNDLED_LIBBPF)
    find_path(LIBBPF_INCLUDE bpf/libbpf.h)
    find_library(LIBBPF_LIB NAMES bpf)
    if(LIBBPF_INCLUDE AND LIBBPF_LIB)
        message(STATUS "Found libbpf: include: ${LIBBPF_INCLUDE}, lib: ${LIBBPF_LIB}")
    else()
        message(FATAL_ERROR "Couldn't find system libbpf")
    endif()
else()
    execute_process(COMMAND uname -m
          COMMAND sed "s/x86_64/x86/"
          COMMAND sed "s/aarch64/arm64/"
          COMMAND sed "s/ppc64le/powerpc/"
          COMMAND sed "s/mips.*/mips/"
          COMMAND sed "s/s390x/s390/"
          OUTPUT_VARIABLE ARCH_output
          ERROR_VARIABLE ARCH_error
          RESULT_VARIABLE ARCH_result
          OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(${ARCH_result} EQUAL 0)
          set(ARCH ${ARCH_output})
          message(STATUS "${MODERN_BPF_LOG_PREFIX} Target arch: ${ARCH}")
    else()
          message(FATAL_ERROR "${MODERN_BPF_LOG_PREFIX} Failed to determine target architecture: ${ARCH_error}")
    endif()

    if(${ARCH} STREQUAL "arm64")
        set(BPF_SYSCALL_NUMBER 280)
    elseif (${ARCH} STREQUAL "x86")
        set(BPF_SYSCALL_NUMBER 321)
    else()
        message(FATAL_ERROR "Unsupported arch for manually setting BPF syscall number: '${ARCH}'")
    endif()

    set(LIBBPF_SRC "${PROJECT_BINARY_DIR}/libbpf-prefix/src")
    set(LIBBPF_BUILD_DIR "${LIBBPF_SRC}/libbpf-build")
    set(LIBBPF_INCLUDE "${LIBBPF_BUILD_DIR}/root/usr/include")
    set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/root/usr/lib64/libbpf.a")
    ExternalProject_Add(
        libbpf
        PREFIX "${PROJECT_BINARY_DIR}/libbpf-prefix"
        DEPENDS zlib libelf
        URL "https://github.com/libbpf/libbpf/archive/refs/tags/v1.0.1.tar.gz"
        URL_HASH
        "SHA256=3d6afde67682c909e341bf194678a8969f17628705af25f900d5f68bd299cb03"
        CONFIGURE_COMMAND mkdir -p build root
        BUILD_COMMAND CFLAGS=-D__NR_bpf=${BPF_SYSCALL_NUMBER} ${CMD_MAKE} BUILD_STATIC_ONLY=y OBJDIR=${LIBBPF_BUILD_DIR}/build DESTDIR=${LIBBPF_BUILD_DIR}/root NO_PKG_CONFIG=1 "EXTRA_CFLAGS=-I${LIBELF_INCLUDE} -I${ZLIB_INCLUDE}" "LDFLAGS=-Wl,-Bstatic" "EXTRA_LDFLAGS=-L${LIBELF_SRC}/libelf/libelf -L${ZLIB_SRC}" -C ${LIBBPF_SRC}/libbpf/src install install_uapi_headers
        INSTALL_COMMAND ""
        UPDATE_COMMAND ""
    )
    message(STATUS "Using bundled libbpf: include'${LIBBPF_INCLUDE}', lib: ${LIBBPF_LIB}")
    install(FILES "${LIBBPF_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
    install(DIRECTORY "${LIBBPF_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
endif()

if(NOT TARGET libbpf)
    add_custom_target(libbpf)
endif()

include_directories(${LIBBPF_INCLUDE})
