#
#    pulseaudio-modules-bt
#
#    Copyright (C) 2018-2019  Huang-Huang Bao
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
if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILE__='\"$(subst ${CMAKE_SOURCE_DIR}/src/,,$(abspath $<))\"'")
endif()

option(CODEC_AAC_FDK "LC-AAC support using fdk-aac(-free)" ON)
option(CODEC_APTX_FF "aptX Classic support using FFmpeg" ON)
option(CODEC_APTX_HD_FF "aptX HD support using FFmpeg" ON)
option(CODEC_LDAC "LDAC encoding, abr support using libldac" ON)
option(FORCE_LARGEST_PA_VERSION "Build for largest available version( <= PulseAudio git master) of PulseAudio" OFF)
option(OFONO_HEADSET "ofono HFP headset support" ON)
option(NATIVE_HEADSET "native HSP headset support" ON)

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-D_REENTRANT)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PulseAudio REQUIRED "libpulse")
pkg_check_modules(DBUS REQUIRED "dbus-1")
pkg_check_modules(SBC REQUIRED "sbc")
pkg_check_modules(AVCODEC libavcodec>=58.18.100)
pkg_check_modules(AVUTIL libavutil>=56.14.100)
pkg_check_modules(FDKAAC "fdk-aac>=0.1.5")
pkg_check_modules(LDACENC "ldacBT-enc")
pkg_check_modules(LDACABR "ldacBT-abr")

set(LDAC_INCLUDE_DIRS ${LDACENC_INCLUDE_DIRS} ${LDACABR_INCLUDE_DIRS})
set(PulseAudio_CORE_LIBDIR ${PulseAudio_LIBDIR}/pulseaudio)
set(MOD_BT_DIR ${PROJECT_SOURCE_DIR}/src/modules/bluetooth)

set(bluez5_util_SOURCES
        ${MOD_BT_DIR}/bluez5-util.c
        ${MOD_BT_DIR}/a2dp/a2dp_sbc.c
        ${MOD_BT_DIR}/a2dp/a2dp_util.c
        )
set(bluez5_util_RPATH "")
set(bluez5_util_LIBS "")

if(${OFONO_HEADSET} STREQUAL "ON")
    set(HAVE_BLUEZ_5_OFONO_HEADSET 1)
    set(bluez5_util_SOURCES ${bluez5_util_SOURCES} ${MOD_BT_DIR}/backend-ofono.c)
    message("[HFP] ofono HFP headset support enabled")
endif()
if(${NATIVE_HEADSET} STREQUAL "ON")
    set(HAVE_BLUEZ_5_NATIVE_HEADSET 1)
    set(bluez5_util_SOURCES ${bluez5_util_SOURCES} ${MOD_BT_DIR}/backend-native.c)
    message("[HSP] native HSP headset support enabled")
endif()

if(${AVCODEC_FOUND} AND ${AVUTIL_FOUND})
    if(${CODEC_APTX_FF} STREQUAL "ON")
        set(PA_A2DP_CODEC_APTX_FF 1)
        message("[A2DP] FFmpeg aptX support enabled")
    endif()
    if(${CODEC_APTX_HD_FF} STREQUAL "ON")
        set(PA_A2DP_CODEC_APTX_HD_FF 1)
        message("[A2DP] FFmpeg aptX HD support enabled")
    endif()

    if ("${PA_A2DP_CODEC_APTX_FF}" OR "${PA_A2DP_CODEC_APTX_HD_FF}")
        set(bluez5_util_SOURCES ${bluez5_util_SOURCES} ${MOD_BT_DIR}/a2dp/a2dp_aptx.c ${MOD_BT_DIR}/a2dp/ffmpeg_libs.c)
        if(NOT "${AVCODEC_LIBRARY_DIRS}" STREQUAL "")
            set(bluez5_util_RPATH ${bluez5_util_RPATH}:${AVCODEC_LIBRARY_DIRS})
        endif()
    endif ()
endif()
if (${FDKAAC_FOUND})
    if(${CODEC_AAC_FDK} STREQUAL "ON")
        set(PA_A2DP_CODEC_AAC_FDK 1)
        set(bluez5_util_SOURCES ${bluez5_util_SOURCES} ${MOD_BT_DIR}/a2dp/a2dp_aac.c)
        set(bluez5_util_LIBS ${bluez5_util_LIBS} ${FDKAAC_LIBRARIES})
        message("[A2DP] fdk-aac LC-AAC support enabled")
    endif()
endif()
if (${LDACENC_FOUND} AND ${LDACABR_FOUND})
    if(${CODEC_LDAC} STREQUAL "ON")
        set(PA_A2DP_CODEC_LDAC 1)
        set(bluez5_util_SOURCES ${bluez5_util_SOURCES} ${MOD_BT_DIR}/a2dp/a2dp_ldac.c ${MOD_BT_DIR}/a2dp/ldac_libs.c)
        if(NOT "${LDACENC_LIBRARY_DIRS}" STREQUAL "")
            set(bluez5_util_RPATH ${bluez5_util_RPATH}:${LDACENC_LIBRARY_DIRS})
        endif()
        message("[A2DP] LDAC support enabled")
    endif()
endif ()

include_directories(.)
include_directories(pa/src)
include_directories(${MOD_BT_DIR})
include_directories(${DBUS_INCLUDE_DIRS})
include_directories(${SBC_INCLUDE_DIRS})
include_directories(${LDAC_INCLUDE_DIRS})
include_directories(${AVCODEC_INCLUDE_DIRS} ${AVUTIL_INCLUDE_DIRS})
include_directories(${FDKAAC_INCLUDE_DIRS})

link_directories(${PulseAudio_CORE_LIBDIR})
link_directories(${PulseAudio_LIBRARY_DIRS})
link_directories(${DBUS_LIBRARY_DIRS})
link_directories(${SBC_LIBRARY_DIRS})
link_directories(${AVCODEC_LIBRARY_DIRS} ${AVUTIL_LIBRARY_DIRS})
link_directories(${FDKAAC_LIBRARY_DIRS})
link_directories(${LDACENC_LIBRARY_DIRS} ${LDACABR_LIBRARY_DIRS})


string(REGEX MATCH "[0-9]+(\\.[0-9]+)" PulseAudio_lib_version ${PulseAudio_VERSION})
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


# libbluez5-util
add_library(bluez5-util SHARED
        ${bluez5_util_SOURCES}
        )
set(bluez5_util_LIBS ${bluez5_util_LIBS} ${SBC_LIBRARIES} ${DBUS_LIBRARIES} ${MOD_LIBS} dl)
target_link_libraries(bluez5-util ${bluez5_util_LIBS})

if(NOT "${bluez5_util_RPATH}" STREQUAL "")
    set(bluez5_util_RPATH "${CMAKE_INSTALL_RPATH}${bluez5_util_RPATH}")
else()
    set(bluez5_util_RPATH "${CMAKE_INSTALL_RPATH}")
endif()
set_target_properties(bluez5-util PROPERTIES
        INSTALL_RPATH "${bluez5_util_RPATH}"
        )

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

