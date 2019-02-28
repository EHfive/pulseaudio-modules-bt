#
#    pulseaudio-modules-bt
#
#    Copyright (C) 2018-2019  Huang-Huang Bao <eh5@sokka.cn>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.10)
project(pulseaudio_modules_bt C)


set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS "$ENV{CFLAGS} -O2 -Wall -Wno-builtin-macro-redefined -Wno-unused -fno-common -DFASTPATH")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILE__='\"$(subst ${CMAKE_SOURCE_DIR}/src/,,$(abspath $<))\"'")

option(FORCE_BUILD_LDAC "Build & Install ldac libraries anyway" OFF)
option(FORCE_NOT_BUILD_LDAC "Don't build ldac libraries anyway" OFF)
option(FORCE_LARGEST_PA_VERSION "Build for largest available version( <= PulseAudio git master) of PulseAudio" OFF)

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
pkg_check_modules(FDKAAC REQUIRED "fdk-aac>=0.1.5")

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
include_directories(${FDKAAC_INCLUDE_DIRS})

link_directories(${PulseAudio_CORE_LIBDIR})


string(REGEX MATCH "[0-9]+(\\.[0-9]+)*" PulseAudio_lib_version ${PulseAudio_VERSION})
if("" STREQUAL "${PulseAudio_lib_version}")
    message(SEND_ERROR "Can't match libpulse version")
    set(PulseAudio_lib_version ${PulseAudio_VERSION})
    message(WARNING "SET PulseAudio_lib_version = ${PulseAudio_VERSION}")
endif()

# Definitions
#   PulseAudio_VERSION_12_N
#       PulseAudio version greater than 12.2
#
#   PulseAudio_VERSION_11_N
#       PulseAudio version greater than 11.1
#
if((${PulseAudio_lib_version} VERSION_GREATER "12.2")
        OR (${FORCE_LARGEST_PA_VERSION} STREQUAL "ON"))
    add_definitions(-DPulseAudio_VERSION_12_N)
elseif(${PulseAudio_lib_version} VERSION_GREATER "11.1")
    add_definitions(-DPulseAudio_VERSION_11_N)
endif()


execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=modlibexecdir libpulse
        OUTPUT_VARIABLE PulseAudio_modlibexecdir
        OUTPUT_STRIP_TRAILING_WHITESPACE)
if("" STREQUAL "${PulseAudio_modlibexecdir}")
    message(SEND_ERROR "Can't found variable modlibexecdir in libpulse.pc")
    set(PulseAudio_modlibexecdir ${PulseAudio_LIBDIR}/pulse-${PulseAudio_lib_version}/modules)
    message(WARNING "SET PulseAudio_modlibexecdir = ${PulseAudio_modlibexecdir}")
endif()


configure_file("${PROJECT_SOURCE_DIR}/config.h.in"  "${PROJECT_SOURCE_DIR}/config.h")

set(MOD_LIBS ${PulseAudio_LIBRARIES} pthread pulsecommon-${PulseAudio_lib_version} pulsecore-${PulseAudio_lib_version})
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
        ${MOD_BT_DIR}/a2dp/a2dp_aac.c
        ${MOD_BT_DIR}/a2dp/a2dp_aptx.c
        ${MOD_BT_DIR}/a2dp/a2dp_ldac.c
        ${MOD_BT_DIR}/a2dp/a2dp_util.c
        )
target_link_libraries(bluez5-util dl ${SBC_LIBRARIES} ${FDKAAC_LIBRARIES} ${DBUS_LIBRARIES} ${MOD_LIBS})

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
        ${MOD_BT_DIR}/module-bluetooth-discover.c
        )

target_compile_definitions(module-bluetooth-discover PUBLIC PA_MODULE_NAME=module_bluetooth_discover)
target_link_libraries(module-bluetooth-discover ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluetooth-discover PROPERTIES PREFIX "")

# module-bluetooth-policy
add_library(module-bluetooth-policy MODULE
        ${MOD_BT_DIR}/module-bluetooth-policy.c
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
