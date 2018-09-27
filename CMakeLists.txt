cmake_minimum_required(VERSION 3.10)
project(pulseaudio_modules_bt C)


set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_FLAGS "$ENV{CFLAGS} -O2 -Wall -fno-common -DFASTPATH")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILE__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DENABLE_LDAC)
add_definitions(-D_REENTRANT)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PulseAudio REQUIRED "libpulse")
pkg_check_modules(DBUS REQUIRED "dbus-1")
pkg_check_modules(SBC REQUIRED "sbc")

set(PulseAudio_CORE_LIBDIR ${PulseAudio_LIBDIR}/pulseaudio)
set(MOD_BT_DIR ${PROJECT_SOURCE_DIR}/src/modules/bluetooth)

include_directories(.)
include_directories(pa/src)
include_directories(${MOD_BT_DIR})
include_directories(${DBUS_INCLUDE_DIRS})
include_directories(${SBC_INCLUDE_DIRS})
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

set(MOD_LIBS ${PulseAudio_LIBRARYS} pthread pulsecore-${PulseAudio_VERSION})
set(CMAKE_INSTALL_RPATH ${PulseAudio_CORE_LIBDIR}:${PulseAudio_modlibexecdir})


# libbluez5-util
add_library(bluez5-util SHARED
        ${MOD_BT_DIR}/backend-native.c
        ${MOD_BT_DIR}/backend-ofono.c
        ${MOD_BT_DIR}/bluez5-util.c
        )
target_link_libraries(bluez5-util ${DBUS_LIBRARIES} ${MOD_LIBS})

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
target_link_libraries(module-bluez5-device bluez5-util ${SBC_LIBRARIES} ${MOD_LIBS})
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
