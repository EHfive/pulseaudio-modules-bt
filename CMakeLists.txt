cmake_minimum_required(VERSION 3.10)
project(pulseaudio_modules_bt C)

include_directories(.)
include_directories(pa/src)
include_directories(libldac/inc)
include_directories(libldac/abr/inc)
link_directories(/usr/lib/pulseaudio)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INSTALL_RPATH /usr/lib/pulseaudio:/usr/lib/pulse-${PulseAudio_VERSION}/modules)

SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-DNDEBUG)
endif (CMAKE_BUILD_TYPE STREQUAL "Release")


add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DENABLE_LDAC)



find_package(PkgConfig REQUIRED)
find_package(PulseAudio  REQUIRED)
pkg_check_modules(DBUS REQUIRED "dbus-1")
pkg_check_modules(SBC REQUIRED "sbc")

include_directories(${DBUS_INCLUDE_DIRS})
include_directories(${SBC_INCLUDE_DIRS})

configure_file("${PROJECT_SOURCE_DIR}/config.h.in"  "${PROJECT_SOURCE_DIR}/config.h")

set(MOD_LIBS ${PULSEAUDIO_LIBRARY} pthread pulsecommon-${PulseAudio_VERSION} pulsecore-${PulseAudio_VERSION})

add_library(ldacBT_enc
        libldac/src/ldaclib.c
        libldac/src/ldacBT.c
        )

target_link_libraries(ldacBT_enc m)

add_library(bluez5-util SHARED
        config.h
        a2dp-codecs.h
        backend-native.c
        backend-ofono.c
        bluez5-util.c
        )
target_link_libraries(bluez5-util ${DBUS_LIBRARIES} ${MOD_LIBS})

add_library(module-bluez5-discover SHARED
        module-bluez5-discover.c
        bluez5-util.h
        config.h
        )
target_compile_definitions(module-bluez5-discover PUBLIC PA_MODULE_NAME=module_bluez5_discover)
target_link_libraries(module-bluez5-discover bluez5-util ${DBUS_LIBRARIES} ${MOD_LIBS})

SET_TARGET_PROPERTIES(module-bluez5-discover PROPERTIES PREFIX "")


add_library(module-bluez5-device SHARED
        module-bluez5-device.c
        bluez5-util.h
        a2dp-codecs.h
        rtp.h
        config.h
        )

target_compile_definitions(module-bluez5-device PUBLIC PA_MODULE_NAME=module_bluez5_device)
target_link_libraries(module-bluez5-device ldacBT_enc bluez5-util ${SBC_LIBRARIES} ${MOD_LIBS})
SET_TARGET_PROPERTIES(module-bluez5-device PROPERTIES PREFIX "")




INSTALL(TARGETS module-bluez5-device  bluez5-util
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/pulse-${PulseAudio_VERSION}/modules/)
