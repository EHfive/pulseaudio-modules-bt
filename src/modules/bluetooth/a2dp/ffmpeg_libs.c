/*
 *  pulseaudio-modules-bt
 *
 *  Copyright  2018-2019  Huang-Huang Bao
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>

#include <libavcodec/avcodec.h>
#include <libavutil/samplefmt.h>

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulsecore/log.h>

#include "ffmpeg_libs.h"

static const char *AVCODEC_LIB_NAMES[] = {
        "libavcodec.so.58",
        "libavcodec.so"
};

static const char *avcodec_find_decoder_func_name = "avcodec_find_decoder";
static const char *avcodec_find_encoder_func_name = "avcodec_find_encoder";
static const char *av_packet_alloc_func_name = "av_packet_alloc";
static const char *av_packet_free_func_name = "av_packet_free";
static const char *avcodec_send_packet_func_name = "avcodec_send_packet";
static const char *avcodec_receive_frame_func_name = "avcodec_receive_frame";
static const char *avcodec_send_frame_func_name = "avcodec_send_frame";
static const char *avcodec_receive_packet_func_name = "avcodec_receive_packet";
static const char *avcodec_flush_buffers_func_name = "avcodec_flush_buffers";
static const char *avcodec_alloc_context3_func_name = "avcodec_alloc_context3";
static const char *avcodec_free_context_func_name = "avcodec_free_context";
static const char *avcodec_open2_func_name = "avcodec_open2";

avcodec_find_decoder_func_t avcodec_find_decoder_func;
avcodec_find_encoder_func_t avcodec_find_encoder_func;
av_packet_alloc_func_t av_packet_alloc_func;
av_packet_free_func_t av_packet_free_func;
avcodec_send_packet_func_t avcodec_send_packet_func;
avcodec_receive_frame_func_t avcodec_receive_frame_func;
avcodec_send_frame_func_t avcodec_send_frame_func;
avcodec_receive_packet_func_t avcodec_receive_packet_func;
avcodec_flush_buffers_func_t avcodec_flush_buffers_func;
avcodec_alloc_context3_func_t avcodec_alloc_context3_func;
avcodec_free_context_func_t avcodec_free_context_func;
avcodec_open2_func_t avcodec_open2_func;

static const char *AVUTIL_LIB_NAMES[] = {
        "libavutil.so.56",
        "libavutil.so"
};

static const char *av_frame_alloc_func_name = "av_frame_alloc";
static const char *av_frame_get_buffer_func_name = "av_frame_get_buffer";
static const char *av_frame_make_writable_func_name = "av_frame_make_writable";
static const char *av_frame_free_func_name = "av_frame_free";

av_frame_alloc_func_t av_frame_alloc_func;
av_frame_get_buffer_func_t av_frame_get_buffer_func;
av_frame_make_writable_func_t av_frame_make_writable_func;
av_frame_free_func_t av_frame_free_func;

static void *libavcodec_h = NULL;

static void *libavutil_h = NULL;


static void *load_func(void *lib_handle, const char *func_name) {
    void *func = dlsym(lib_handle, func_name);
    if (func == NULL) {
        pa_log_error("No function %s in provide library. %s", func_name, dlerror());
        return NULL;
    }
    return func;
}

static void libavcodec_unload() {
    avcodec_find_decoder_func = NULL;
    avcodec_find_encoder_func = NULL;
    av_packet_alloc_func = NULL;
    av_packet_free_func = NULL;
    avcodec_send_packet_func = NULL;
    avcodec_receive_frame_func = NULL;
    avcodec_send_frame_func = NULL;
    avcodec_receive_packet_func = NULL;
    avcodec_flush_buffers_func = NULL;
    avcodec_alloc_context3_func = NULL;
    avcodec_free_context_func = NULL;
    avcodec_open2_func = NULL;
    if (libavcodec_h) {
        dlclose(libavcodec_h);
        libavcodec_h = NULL;
    }
}

static void libavutil_unload() {
    av_frame_alloc_func = NULL;
    av_frame_get_buffer_func = NULL;
    av_frame_make_writable_func = NULL;
    av_frame_free_func = NULL;
    if (libavutil_h) {
        dlclose(libavutil_h);
        libavutil_h = NULL;
    }
}

static bool libavcodec_load() {
    if (libavcodec_h)
        return true;
    for (int i = 0; i < PA_ELEMENTSOF(AVCODEC_LIB_NAMES); ++i) {
        libavutil_unload();
        libavcodec_h = dlopen(AVCODEC_LIB_NAMES[i], RTLD_NOW);
        if (libavcodec_h == NULL) {
            pa_log_warn("Cannot open libavcodec library: %s. %s", AVCODEC_LIB_NAMES[i], dlerror());
            continue;
        }
        avcodec_find_decoder_func = load_func(libavcodec_h, avcodec_find_decoder_func_name);
        if (avcodec_find_decoder_func == NULL)
            continue;
        avcodec_find_encoder_func = load_func(libavcodec_h, avcodec_find_encoder_func_name);
        if (avcodec_find_encoder_func == NULL)
            continue;
        av_packet_alloc_func = load_func(libavcodec_h, av_packet_alloc_func_name);
        if (av_packet_alloc_func == NULL)
            continue;
        av_packet_free_func = load_func(libavcodec_h, av_packet_free_func_name);
        if (av_packet_free_func == NULL)
            continue;
        avcodec_send_packet_func = load_func(libavcodec_h, avcodec_send_packet_func_name);
        if (avcodec_send_packet_func == NULL)
            continue;
        avcodec_receive_frame_func = load_func(libavcodec_h, avcodec_receive_frame_func_name);
        if (avcodec_receive_frame_func == NULL)
            continue;
        avcodec_send_frame_func = load_func(libavcodec_h, avcodec_send_frame_func_name);
        if (avcodec_send_frame_func == NULL)
            continue;
        avcodec_receive_packet_func = load_func(libavcodec_h, avcodec_receive_packet_func_name);
        if (avcodec_receive_packet_func == NULL)
            continue;
        avcodec_flush_buffers_func = load_func(libavcodec_h, avcodec_flush_buffers_func_name);
        if (avcodec_flush_buffers_func == NULL)
            continue;
        avcodec_alloc_context3_func = load_func(libavcodec_h, avcodec_alloc_context3_func_name);
        if (avcodec_alloc_context3_func == NULL)
            continue;
        avcodec_free_context_func = load_func(libavcodec_h, avcodec_free_context_func_name);
        if (avcodec_free_context_func == NULL)
            continue;
        avcodec_open2_func = load_func(libavcodec_h, avcodec_open2_func_name);
        if (avcodec_open2_func == NULL)
            continue;
        return true;
    }
    return false;
}

static bool libavutil_load() {
    if (libavutil_h)
        return true;
    for (int i = 0; i < PA_ELEMENTSOF(AVUTIL_LIB_NAMES); ++i) {
        libavutil_h = dlopen(AVUTIL_LIB_NAMES[i], RTLD_NOW);
        if (libavutil_h == NULL) {
            pa_log_warn("Cannot open libavutil library: %s. %s", AVUTIL_LIB_NAMES[i], dlerror());
            continue;
        }
        av_frame_alloc_func = load_func(libavutil_h, av_frame_alloc_func_name);
        if (av_frame_alloc_func == NULL)
            continue;
        av_frame_get_buffer_func = load_func(libavutil_h, av_frame_get_buffer_func_name);
        if (av_frame_get_buffer_func == NULL)
            continue;
        av_frame_make_writable_func = load_func(libavutil_h, av_frame_make_writable_func_name);
        if (av_frame_make_writable_func == NULL)
            continue;
        av_frame_free_func = load_func(libavutil_h, av_frame_free_func_name);
        if (av_frame_free_func == NULL)
            continue;
        return true;
    }

    return false;
}

bool ffmpeg_libs_load() {
    if (libavcodec_load() && libavutil_load())
        return true;
    libavcodec_unload();
    libavutil_unload();
    return false;
}