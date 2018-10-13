#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>

#include <libavcodec/avcodec.h>
#include <libavutil/samplefmt.h>

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulsecore/log.h>

static const char *AVCODEC_LIB_NAME = "libavcodec.so";

static const char *avcodec_find_decoder_func_name = "avcodec_find_decoder";
static const char *avcodec_find_encoder_func_name = "avcodec_find_encoder";
static const char *av_packet_alloc_func_name = "av_packet_alloc";
static const char *av_packet_free_func_name = "av_packet_free";
static const char *avcodec_send_packet_func_name = "avcodec_send_packet";
static const char *avcodec_receive_frame_func_name = "avcodec_receive_frame";
static const char *avcodec_send_frame_func_name = "avcodec_send_frame";
static const char *avcodec_receive_packet_func_name = "avcodec_receive_packet";
static const char *avcodec_alloc_context3_func_name = "avcodec_alloc_context3";
static const char *avcodec_free_context_func_name = "avcodec_free_context";
static const char *avcodec_open2_func_name = "avcodec_open2";

typedef AVCodec *(*avcodec_find_decoder_func_t)(enum AVCodecID id);

typedef AVCodec *(*avcodec_find_encoder_func_t)(enum AVCodecID id);

typedef AVPacket *(*av_packet_alloc_func_t)(void);

typedef void (*av_packet_free_func_t)(AVPacket **pkt);

typedef int (*avcodec_send_packet_func_t)(AVCodecContext *avctx, const AVPacket *avpkt);

typedef int (*avcodec_receive_frame_func_t)(AVCodecContext *avctx, AVFrame *frame);

typedef int (*avcodec_send_frame_func_t)(AVCodecContext *avctx, const AVFrame *frame);

typedef int (*avcodec_receive_packet_func_t)(AVCodecContext *avctx, AVPacket *avpkt);

typedef AVCodecContext *(*avcodec_alloc_context3_func_t)(const AVCodec *codec);

typedef void (*avcodec_free_context_func_t)(AVCodecContext **avctx);

typedef int (*avcodec_open2_func_t)(AVCodecContext *avctx, const AVCodec *codec, AVDictionary **options);


static avcodec_find_decoder_func_t avcodec_find_decoder_func;
static avcodec_find_encoder_func_t avcodec_find_encoder_func;
static av_packet_alloc_func_t av_packet_alloc_func;
static av_packet_free_func_t av_packet_free_func;
static avcodec_send_packet_func_t avcodec_send_packet_func;
static avcodec_receive_frame_func_t avcodec_receive_frame_func;
static avcodec_send_frame_func_t avcodec_send_frame_func;
static avcodec_receive_packet_func_t avcodec_receive_packet_func;
static avcodec_alloc_context3_func_t avcodec_alloc_context3_func;
static avcodec_free_context_func_t avcodec_free_context_func;
static avcodec_open2_func_t avcodec_open2_func;

static const char *AVUTIL_LIB_NAME = "libavutil.so";

static const char *av_frame_alloc_func_name = "av_frame_alloc";
static const char *av_frame_get_buffer_func_name = "av_frame_get_buffer";
static const char *av_frame_make_writable_func_name = "av_frame_make_writable";
static const char *av_frame_free_func_name = "av_frame_free";


typedef AVFrame *(*av_frame_alloc_func_t)(void);


typedef int (*av_frame_get_buffer_func_t)(AVFrame *frame, int align);

typedef int (*av_frame_make_writable_func_t)(AVFrame *frame);

typedef void (*av_frame_free_func_t)(AVFrame **frame);


static av_frame_alloc_func_t av_frame_alloc_func;
static av_frame_get_buffer_func_t av_frame_get_buffer_func;
static av_frame_make_writable_func_t av_frame_make_writable_func;
static av_frame_free_func_t av_frame_free_func;


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
    avcodec_alloc_context3_func = NULL;
    avcodec_free_context_func = NULL;
    avcodec_open2_func = NULL;
    if (libavcodec_h) {
        dlclose(libavcodec_h);
        libavcodec_h = NULL;
    }
}

static bool libavcodec_load() {
    if (libavcodec_h)
        return true;
    libavcodec_h = dlopen(AVCODEC_LIB_NAME, RTLD_NOW);
    if (libavcodec_h == NULL) {
        pa_log_error("Cannot open libavcodec library: %s. %s", AVCODEC_LIB_NAME, dlerror());
        return false;
    }
    avcodec_find_decoder_func = load_func(libavcodec_h, avcodec_find_decoder_func_name);
    if (avcodec_find_decoder_func == NULL)
        return false;
    avcodec_find_encoder_func = load_func(libavcodec_h, avcodec_find_encoder_func_name);
    if (avcodec_find_encoder_func == NULL)
        return false;
    av_packet_alloc_func = load_func(libavcodec_h, av_packet_alloc_func_name);
    if (av_packet_alloc_func == NULL)
        return false;
    av_packet_free_func = load_func(libavcodec_h, av_packet_free_func_name);
    if (av_packet_free_func == NULL)
        return false;
    avcodec_send_packet_func = load_func(libavcodec_h, avcodec_send_packet_func_name);
    if (avcodec_send_packet_func == NULL)
        return false;
    avcodec_receive_frame_func = load_func(libavcodec_h, avcodec_receive_frame_func_name);
    if (avcodec_receive_frame_func == NULL)
        return false;
    avcodec_send_frame_func = load_func(libavcodec_h, avcodec_send_frame_func_name);
    if (avcodec_send_frame_func == NULL)
        return false;
    avcodec_receive_packet_func = load_func(libavcodec_h, avcodec_receive_packet_func_name);
    if (avcodec_receive_packet_func == NULL)
        return false;
    avcodec_alloc_context3_func = load_func(libavcodec_h, avcodec_alloc_context3_func_name);
    if (avcodec_alloc_context3_func == NULL)
        return false;
    avcodec_free_context_func = load_func(libavcodec_h, avcodec_free_context_func_name);
    if (avcodec_free_context_func == NULL)
        return false;
    avcodec_open2_func = load_func(libavcodec_h, avcodec_open2_func_name);
    if (avcodec_open2_func == NULL)
        return false;
    return true;
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

static bool libavutil_load() {
    if (libavutil_h)
        return true;
    libavutil_h = dlopen(AVUTIL_LIB_NAME, RTLD_NOW);
    if (libavutil_h == NULL) {
        pa_log_error("Cannot open libavutil library: %s. %s", AVUTIL_LIB_NAME, dlerror());
        return false;
    }
    av_frame_alloc_func = load_func(libavutil_h, av_frame_alloc_func_name);
    if (av_frame_alloc_func == NULL)
        return false;
    av_frame_get_buffer_func = load_func(libavutil_h, av_frame_get_buffer_func_name);
    if (av_frame_get_buffer_func == NULL)
        return false;
    av_frame_make_writable_func = load_func(libavutil_h, av_frame_make_writable_func_name);
    if (av_frame_make_writable_func == NULL)
        return false;
    av_frame_free_func = load_func(libavutil_h, av_frame_free_func_name);
    if (av_frame_free_func == NULL)
        return false;

    return true;
}

static bool aptx_libs_load() {
    if (libavcodec_load() && libavutil_load())
        return true;
    libavcodec_unload();
    libavutil_unload();
    return false;
}