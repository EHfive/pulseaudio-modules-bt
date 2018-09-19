cmake_minimum_required(VERSION 3.10)
project(pulseaudio_modules_bt C)

include_directories(.)
include_directories(pa/src)
include_directories(libldac/inc)
include_directories(libldac/abr/inc)
link_directories(${CMAKE_INSTALL_PREFIX}/lib/pulseaudio)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS "$ENV{CFLAGS} -O2 -Wall -fno-common -DFASTPATH")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILE__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DENABLE_LDAC)

add_definitions(-D_REENTRANT)

find_package(PkgConfig REQUIRED)
find_package(PulseAudio  REQUIRED)
pkg_check_modules(DBUS REQUIRED "dbus-1")
pkg_check_modules(SBC REQUIRED "sbc")

include_directories(${DBUS_INCLUDE_DIRS})
include_directories(${SBC_INCLUDE_DIRS})

configure_file("${PROJECT_SOURCE_DIR}/config.h.in"  "${PROJECT_SOURCE_DIR}/config.h")

set(MOD_LIBS ${PULSEAUDIO_LIBRARY} pthread)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib/pulseaudio:${CMAKE_INSTALL_PREFIX}/lib/pulse-${PulseAudio_VERSION}/modules)

# libldacBT_enc
add_library(ldacBT_enc SHARED
        libldac/src/ldaclib.c
        libldac/src/ldacBT.c
        libldac/abr/src/ldacBT_abr.c
        )

target_link_libraries(ldacBT_enc m)

# libbluez5-util
add_library(bluez5-util SHARED
        config.h
        a2dp-codecs.h
        backend-native.c
        backend-ofono.c
        bluez5-util.c
        )
target_link_libraries(bluez5-util ${DBUS_LIBRARIES} ${MOD_LIBS})

# module-bluez5-discover
add_library(module-bluez5-discover MODULE
        module-bluez5-discover.c
        bluez5-util.h
        config.h
        )
target_compile_definitions(module-bluez5-discover PUBLIC PA_MODULE_NAME=module_bluez5_discover)
target_link_libraries(module-bluez5-discover bluez5-util ${DBUS_LIBRARIES} ${MOD_LIBS})

SET_TARGET_PROPERTIES(module-bluez5-discover PROPERTIES PREFIX "")


# module-bluez5-device
add_library(module-bluez5-device MODULE
        module-bluez5-device.c
        bluez5-util.h
        a2dp-codecs.h
        rtp.h
        config.h
        )

target_compile_definitions(module-bluez5-device PUBLIC PA_MODULE_NAME=module_bluez5_device)
target_link_libraries(module-bluez5-device ldacBT_enc bluez5-util ${SBC_LIBRARIES} ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluez5-device PROPERTIES PREFIX "")

# module-bluetooth-discover
add_library(module-bluetooth-discover MODULE
        config.h
        ${PROJECT_SOURCE_DIR}/pa/src/pulsecore/module.h
        ${PROJECT_SOURCE_DIR}/pa/src/modules/bluetooth/module-bluetooth-discover.c
        )

target_compile_definitions(module-bluetooth-discover PUBLIC PA_MODULE_NAME=module_bluetooth_discover)
target_link_libraries(module-bluetooth-discover  ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluetooth-discover PROPERTIES PREFIX "")

# module-bluetooth-policy
add_library(module-bluetooth-policy MODULE
        config.h
        ${PROJECT_SOURCE_DIR}/pa/src/pulsecore/module.h
        ${PROJECT_SOURCE_DIR}/pa/src/modules/bluetooth/module-bluetooth-policy.c
        )

target_compile_definitions(module-bluetooth-policy PUBLIC PA_MODULE_NAME=module_bluetooth_policy)
target_link_libraries(module-bluetooth-policy  ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluetooth-policy PROPERTIES PREFIX "")

message(STATUS "CMAKE_C_FLAGS = " ${CMAKE_C_FLAGS})

INSTALL(TARGETS ldacBT_enc module-bluez5-device module-bluez5-discover bluez5-util module-bluetooth-policy module-bluetooth-discover
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/pulse-${PulseAudio_VERSION}/modules/)
