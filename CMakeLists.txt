cmake_minimum_required(VERSION 3.10)
project(pulseaudio_modules_bt C)


set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS "$ENV{CFLAGS} -O2 -Wall -Wno-builtin-macro-redefined -Wno-unused -fno-common -DFASTPATH")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILE__='\"$(subst ${CMAKE_SOURCE_DIR}/src/,,$(abspath $<))\"'")

option(FORCE_BUILD_LDAC "Build & Install ldac libraries anyway" OFF)
option(FORCE_NOT_BUILD_LDAC "Don't build ldac libraries anyway" OFF)

if(("${FORCE_BUILD_LDAC}" STREQUAL "ON") AND ("${FORCE_NOT_BUILD_LDAC}" STREQUAL "ON"))
    message(FATAL_ERROR "FORCE_BUILD_LDAC and FORCE_NOT_BUILD_LDAC enabled sametime")
endif()

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-D_REENTRANT)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PulseAudio REQUIRED "libpulse")
pkg_check_modules(DBUS REQUIRED "dbus-1")
pkg_check_modules(SBC REQUIRED "sbc")
pkg_check_modules(AVCODEC REQUIRED libavcodec>=58.18.100)
pkg_check_modules(AVUTIL REQUIRED libavutil>=56.14.100)

pkg_check_modules(LDACENC "ldacBT-enc")
pkg_check_modules(LDACABR "ldacBT-abr")

if (("${LDACENC_FOUND}" AND "${LDACABR_FOUND}" AND ("${FORCE_BUILD_LDAC}" STREQUAL "OFF"))
        OR ("${FORCE_NOT_BUILD_LDAC}" STREQUAL "ON"))
    set(HAVE_SYSTEM_LDAC 1)
    pkg_check_modules(LDACENC REQUIRED "ldacBT-enc")
    pkg_check_modules(LDACABR REQUIRED "ldacBT-abr")
    set(LDAC_INCLUDE_DIRS ${LDACENC_INCLUDE_DIRS} ${LDACABR_INCLUDE_DIRS})
else()
    set(HAVE_SYSTEM_LDAC 0)
    set(LDAC_INCLUDE_DIRS libldac/inc libldac/abr/inc)
endif()

set(PulseAudio_CORE_LIBDIR ${PulseAudio_LIBDIR}/pulseaudio)
set(MOD_BT_DIR ${PROJECT_SOURCE_DIR}/src/modules/bluetooth)

include_directories(.)
include_directories(pa/src)
include_directories(${MOD_BT_DIR})
include_directories(${DBUS_INCLUDE_DIRS})
include_directories(${SBC_INCLUDE_DIRS})
include_directories(${LDAC_INCLUDE_DIRS})
include_directories(${AVCODEC_INCLUDE_DIRS} ${AVUTIL_INCLUDE_DIRS})

link_directories(${PulseAudio_CORE_LIBDIR})

execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=modlibexecdir libpulse
        OUTPUT_VARIABLE PulseAudio_modlibexecdir
        OUTPUT_STRIP_TRAILING_WHITESPACE)
if("" STREQUAL "${PulseAudio_modlibexecdir}")
    message(SEND_ERROR "Can't found variable modlibexecdir in libpulse.pc")
    set(PulseAudio_modlibexecdir ${PulseAudio_LIBDIR}/pulse-${PulseAudio_VERSION}/modules)
    message(WARNING "SET PulseAudio_modlibexecdir = ${PulseAudio_modlibexecdir}")
endif()


configure_file("${PROJECT_SOURCE_DIR}/config.h.in"  "${PROJECT_SOURCE_DIR}/config.h")

set(MOD_LIBS ${PulseAudio_LIBRARIES} pthread pulsecommon-${PulseAudio_VERSION} pulsecore-${PulseAudio_VERSION})
set(CMAKE_INSTALL_RPATH ${PulseAudio_CORE_LIBDIR}:${PulseAudio_modlibexecdir})

if(NOT ${HAVE_SYSTEM_LDAC})
# libldacBT_enc
add_library(ldacBT_enc SHARED
        libldac/src/ldaclib.c
        libldac/src/ldacBT.c

        )

target_link_libraries(ldacBT_enc m)

add_library(ldacBT_abr SHARED
        libldac/abr/src/ldacBT_abr.c
        )
target_link_libraries(ldacBT_abr ldacBT_enc)

endif()

# libbluez5-util
add_library(bluez5-util SHARED
        ${MOD_BT_DIR}/backend-native.c
        ${MOD_BT_DIR}/backend-ofono.c
        ${MOD_BT_DIR}/bluez5-util.c
        ${MOD_BT_DIR}/a2dp/a2dp_sbc.c
        ${MOD_BT_DIR}/a2dp/a2dp_aptx.c
        ${MOD_BT_DIR}/a2dp/a2dp_ldac.c
        ${MOD_BT_DIR}/a2dp/a2dp_util.c
        )
target_link_libraries(bluez5-util dl ${SBC_LIBRARIES} ${DBUS_LIBRARIES} ${MOD_LIBS})

# module-bluez5-discover
add_library(module-bluez5-discover MODULE
        ${MOD_BT_DIR}/module-bluez5-discover.c
        )
target_compile_definitions(module-bluez5-discover PUBLIC PA_MODULE_NAME=module_bluez5_discover)
target_link_libraries(module-bluez5-discover bluez5-util ${DBUS_LIBRARIES} ${MOD_LIBS})

SET_TARGET_PROPERTIES(module-bluez5-discover PROPERTIES PREFIX "")


# module-bluez5-device
add_library(module-bluez5-device MODULE
        ${MOD_BT_DIR}/module-bluez5-device.c
        )

target_compile_definitions(module-bluez5-device PUBLIC PA_MODULE_NAME=module_bluez5_device)
target_link_libraries(module-bluez5-device bluez5-util ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluez5-device PROPERTIES PREFIX "")

# module-bluetooth-discover
add_library(module-bluetooth-discover MODULE
        ${PROJECT_SOURCE_DIR}/pa/src/modules/bluetooth/module-bluetooth-discover.c
        )

target_compile_definitions(module-bluetooth-discover PUBLIC PA_MODULE_NAME=module_bluetooth_discover)
target_link_libraries(module-bluetooth-discover ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluetooth-discover PROPERTIES PREFIX "")

# module-bluetooth-policy
add_library(module-bluetooth-policy MODULE
        ${PROJECT_SOURCE_DIR}/pa/src/modules/bluetooth/module-bluetooth-policy.c
        )

target_compile_definitions(module-bluetooth-policy PUBLIC PA_MODULE_NAME=module_bluetooth_policy)
target_link_libraries(module-bluetooth-policy  ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluetooth-policy PROPERTIES PREFIX "")

message(STATUS "CMAKE_C_FLAGS = " ${CMAKE_C_FLAGS})

INSTALL(TARGETS
        bluez5-util
        module-bluez5-discover
        module-bluez5-device
        module-bluetooth-discover
        module-bluetooth-policy
        LIBRARY DESTINATION ${PulseAudio_modlibexecdir})

if(NOT ${HAVE_SYSTEM_LDAC})

INSTALL(TARGETS
        ldacBT_enc
        ldacBT_abr
        LIBRARY DESTINATION ${PulseAudio_modlibexecdir})

endif()
