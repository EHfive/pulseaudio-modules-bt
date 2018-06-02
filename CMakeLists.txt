cmake_minimum_required(VERSION 3.10)
project(pulseaudio_modules_bt C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_definitions(-DHAVE_CONFIG_H)


find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED "dbus-1")

include_directories(.)
include_directories(pa/src)
include_directories(libldac/inc)
include_directories(libldac/abr/inc)
include_directories(${DBUS_INCLUDE_DIRS})


add_library(ldacBT_enc
        libldac/src/ldaclib.c
        libldac/src/ldacBT.c
        )
target_link_libraries(ldacBT_enc m)


add_library(module-bluez5-device SHARED
        module-bluez5-device.c
        bluez5-util.c
        a2dp-codecs.h
        rtp.h
        config.h
        )

target_link_libraries(module-bluez5-device ldacBT_enc)
