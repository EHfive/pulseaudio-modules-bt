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

#include <arpa/inet.h>
#include <string.h>

#include <libavcodec/avcodec.h>
#include <libavutil/samplefmt.h>

#include <pulse/xmalloc.h>

#include "a2dp-api.h"

#include "ffmpeg_libs.h"

#define streq(a, b) (!strcmp((a),(b)))


typedef struct aptx_info {
    pa_a2dp_source_read_cb_t read_pcm;
    pa_a2dp_source_read_buf_free_cb_t read_buf_free;

    bool is_a2dp_sink;
    bool is_hd;

    size_t aptx_frame_size;
    int nb_samples;
    const AVCodec *av_codec;
    AVCodecContext *av_codec_ctx;
    int channel_mode;
    uint16_t seq_num;


    size_t block_size;


} aptx_info_t;

static const AVCodec *av_codec_aptx_decoder = NULL;
static const AVCodec *av_codec_aptx_encoder = NULL;

static const AVCodec *av_codec_aptx_hd_decoder = NULL;
static const AVCodec *av_codec_aptx_hd_encoder = NULL;


static bool pa_aptx_decoder_load() {
    if(!ffmpeg_libs_load())
        return false;
    if (av_codec_aptx_decoder)
        return true;
    av_codec_aptx_decoder = avcodec_find_decoder_func(AV_CODEC_ID_APTX);
    if (!av_codec_aptx_decoder) {
        pa_log_debug("Cannot find APTX decoder in FFmpeg avcodec library");
        return false;
    }

    return true;
}

static bool pa_aptx_encoder_load() {
    if(!ffmpeg_libs_load())
        return false;
    if (av_codec_aptx_encoder)
        return true;
    av_codec_aptx_encoder = avcodec_find_encoder_func(AV_CODEC_ID_APTX);
    if (!av_codec_aptx_encoder) {
        pa_log_debug("Cannot find APTX encoder in FFmpeg avcodec library");
        return false;
    }

    return true;
}

static bool pa_aptx_hd_decoder_load() {
    if(!ffmpeg_libs_load())
        return false;
    if (av_codec_aptx_hd_decoder)
        return true;
    av_codec_aptx_hd_decoder = avcodec_find_decoder_func(AV_CODEC_ID_APTX_HD);
    if (!av_codec_aptx_hd_decoder) {
        pa_log_debug("Cannot find APTX HD decoder in FFmpeg avcodec library");
        return false;
    }

    return true;
}

static bool pa_aptx_hd_encoder_load() {
    if(!ffmpeg_libs_load())
        return false;
    if (av_codec_aptx_hd_encoder)
        return true;
    av_codec_aptx_hd_encoder = avcodec_find_encoder_func(AV_CODEC_ID_APTX_HD);
    if (!av_codec_aptx_hd_encoder) {
        pa_log_debug("Cannot find APTX HD encoder in FFmpeg avcodec library");
        return false;
    }

    return true;
}

static bool _internal_pa_dual_decoder_init(bool is_hd, void **codec_data) {
    aptx_info_t *info = pa_xmalloc0(sizeof(aptx_info_t));
    *codec_data = info;
    info->is_hd = is_hd;
    info->is_a2dp_sink = true;
    info->aptx_frame_size = is_hd ? 6 : 4;
    info->av_codec = is_hd ? av_codec_aptx_hd_decoder : av_codec_aptx_decoder;
    return true;
}

static bool
_internal_pa_dual_encoder_init(bool is_hd, pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb,
                               void **codec_data) {
    aptx_info_t *info = pa_xmalloc0(sizeof(aptx_info_t));
    *codec_data = info;
    info->is_hd = is_hd;
    info->is_a2dp_sink = false;
    info->read_pcm = read_cb;
    info->read_buf_free = free_cb;
    info->aptx_frame_size = is_hd ? 6 : 4;
    info->av_codec = is_hd ? av_codec_aptx_hd_encoder : av_codec_aptx_encoder;
    return true;
}

static int pa_dual_update_user_config(pa_proplist *user_config, void **codec_data) {
    return 0;
}

static size_t
pa_dual_decode(const void *read_buf, size_t read_buf_size, void *write_buf, size_t write_buf_size, size_t *_decoded,
               uint32_t *timestamp, void **codec_data) {
    const struct rtp_header *header;
    void *p;
    int ret = 1;
    size_t i;
    AVPacket *pkt;
    size_t to_decode;
    size_t total_written = 0;
    AVFrame *av_frame = NULL;
    aptx_info_t *aptx_info = *codec_data;


    pa_assert(aptx_info);
    pa_assert(aptx_info->av_codec);
    pa_assert(aptx_info->av_codec_ctx);

    if (aptx_info->is_hd) {
        header = read_buf;

        *timestamp = ntohl(header->timestamp);

        p = (uint8_t *) read_buf + sizeof(*header);
        to_decode = read_buf_size - sizeof(*header);
    } else {
        *timestamp = (uint32_t) -1;

        p = (uint8_t *) read_buf;
        to_decode = read_buf_size;
    }

    av_frame = av_frame_alloc_func();
    pkt = av_packet_alloc_func();
    pkt->data = p;
    pkt->size = (int) to_decode;


    *_decoded = 0;

    while(ret){
        ret = avcodec_send_packet_func(aptx_info->av_codec_ctx, pkt);
        if (PA_UNLIKELY(ret == AVERROR(EINVAL))) {
            avcodec_flush_buffers_func(aptx_info->av_codec_ctx);
            continue;
        } else if (PA_UNLIKELY(ret < 0 && ret != AVERROR(EAGAIN))) {
            pa_log_debug("Error submitting the packet to the decoder");
            goto done;
        }
        ret = avcodec_receive_frame_func(aptx_info->av_codec_ctx, av_frame);
        if (PA_UNLIKELY(ret < 0)) {
            pa_log_debug("Error during decoding");
            goto done;
        }
    }

    *_decoded = aptx_info->aptx_frame_size * av_frame->nb_samples / 4;

    total_written = (size_t) av_frame->nb_samples * (4 * 2);

    pa_assert_fp(_decoded <= read_buf_size);
    pa_assert_fp(total_written <= write_buf_size);

    for (i = 0; i < av_frame->nb_samples * sizeof(uint32_t); i += sizeof(uint32_t)) {
        memcpy((uint8_t *) write_buf + i * 2, av_frame->data[0] + i, sizeof(uint32_t));
        memcpy((uint8_t *) write_buf + i * 2 + sizeof(uint32_t), av_frame->data[1] + i, sizeof(uint32_t));
    }

done:
    av_frame_free_func(&av_frame);
    av_packet_free_func(&pkt);
    return total_written;
}

static size_t
pa_dual_encode(uint32_t timestamp, void *write_buf, size_t write_buf_size, size_t *_encoded, void *read_cb_data,
               void **codec_data) {
    struct rtp_header *header;
    size_t nbytes;
    void *d;
    const void *p;
    AVFrame *av_frame;
    AVPacket *pkt;
    aptx_info_t *aptx_info = *codec_data;
    int ret;
    size_t i;

    pa_assert(aptx_info);
    pa_assert(aptx_info->av_codec);
    pa_assert(aptx_info->av_codec_ctx);

    pa_assert_fp(aptx_info->av_codec_ctx->frame_size <= write_buf_size);

    aptx_info->read_pcm(&p, (size_t) aptx_info->block_size, read_cb_data);

    if (aptx_info->is_hd) {
        header = write_buf;
        memset(write_buf, 0, sizeof(*header));
        header->v = 2;
        header->pt = 96;
        header->sequence_number = htons(aptx_info->seq_num++);
        header->timestamp = htonl(timestamp);
        header->ssrc = htonl(1);
        d = (uint8_t *) write_buf + sizeof(*header);
    } else {
        d = (uint8_t *) write_buf;
    }

    av_frame = av_frame_alloc_func();
    av_frame->nb_samples = aptx_info->nb_samples;
    av_frame->format = aptx_info->av_codec_ctx->sample_fmt;
    av_frame->channel_layout = aptx_info->av_codec_ctx->channel_layout;

    pkt = av_packet_alloc_func();

    pa_assert_se(av_frame_get_buffer_func(av_frame, 0) >= 0);
    pa_assert_se(av_frame_make_writable_func(av_frame) >= 0);


    for (i = 0; i < av_frame->nb_samples * sizeof(uint32_t); i += sizeof(uint32_t)) {
        memcpy(av_frame->data[0] + i, (uint8_t *) p + i * 2, sizeof(uint32_t));
        memcpy(av_frame->data[1] + i, (uint8_t *) p + i * 2 + sizeof(uint32_t), sizeof(uint32_t));
    }
    *_encoded = 0;

    ret = avcodec_send_frame_func(aptx_info->av_codec_ctx, av_frame);

    if (PA_UNLIKELY(ret < 0)) {
        fprintf(stderr, "Error sending the frame to the encoder\n");
        nbytes = 0;
        goto done;
    }

    ret = avcodec_receive_packet_func(aptx_info->av_codec_ctx, pkt);

    if (PA_UNLIKELY(ret != 0)) {
        fprintf(stderr, "Error receiving the packet from the encoder\n");
        nbytes = 0;
        goto done;
    }

    memcpy(d, pkt->data, (size_t) pkt->size);
    d = (uint8_t *) d + pkt->size;

    nbytes = (uint8_t *) d - (uint8_t *) write_buf;
    *_encoded += aptx_info->block_size;

done:
    av_frame_free_func(&av_frame);
    av_packet_free_func(&pkt);
    aptx_info->read_buf_free(&p, read_cb_data);
    return nbytes;
}

static void
pa_dual_config_transport(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                         pa_sample_spec *sample_spec, void **codec_data) {
    aptx_info_t *aptx_info = *codec_data;
    a2dp_aptx_t *config = (a2dp_aptx_t *) configuration;
    AVCodecContext *aptx_ctx;
    pa_assert(aptx_info);
    pa_assert(aptx_info->av_codec);
    pa_assert_se(configuration_size == (aptx_info->is_hd ? sizeof(a2dp_aptx_hd_t) : sizeof(a2dp_aptx_t)));

    if (aptx_info->av_codec_ctx)
        avcodec_free_context_func(&aptx_info->av_codec_ctx);

    aptx_info->av_codec_ctx = avcodec_alloc_context3_func(aptx_info->av_codec);
    aptx_ctx = aptx_info->av_codec_ctx;

    aptx_ctx->sample_fmt = AV_SAMPLE_FMT_S32P;
    sample_spec->format = PA_SAMPLE_S32LE;

    switch (config->frequency) {
        case APTX_SAMPLING_FREQ_16000:
            aptx_ctx->sample_rate = 16000;
            aptx_ctx->bit_rate = 16000;
            sample_spec->rate = 16000U;
            break;
        case APTX_SAMPLING_FREQ_32000:
            aptx_ctx->sample_rate = 32000;
            aptx_ctx->bit_rate = 32000;
            sample_spec->rate = 32000U;
            break;
        case APTX_SAMPLING_FREQ_44100:
            aptx_ctx->sample_rate = 44100;
            aptx_ctx->bit_rate = 44100;
            sample_spec->rate = 44100U;
            break;
        case APTX_SAMPLING_FREQ_48000:
            aptx_ctx->sample_rate = 48000;
            aptx_ctx->bit_rate = 48000;
            sample_spec->rate = 48000U;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->channel_mode) {
        case APTX_CHANNEL_MODE_STEREO:
            aptx_ctx->channel_layout = AV_CH_LAYOUT_STEREO;
            aptx_ctx->channels = 2;
            sample_spec->channels = 2;
            break;
        default:
            pa_assert_not_reached();
    }

    pa_assert_se(avcodec_open2_func(aptx_info->av_codec_ctx, aptx_info->av_codec, NULL) == 0);

};

static void pa_dual_get_read_block_size(size_t read_link_mtu, size_t *read_block_size, void **codec_data) {
    aptx_info_t *aptx_info = *codec_data;
    size_t aptx_frame_size = aptx_info->aptx_frame_size;
    size_t rtp_use_size = aptx_info->is_hd ? sizeof(struct rtp_header) : 0;
    pa_assert(aptx_info);

    /*
    　* PCM 32-bit, 2 channel (4 bytes * 2)
    　* PCM frames/APTX frames == 4
    　* */
    *read_block_size = (read_link_mtu - rtp_use_size) / aptx_frame_size * (4 * 2) * 4;
    aptx_info->block_size = *read_block_size;
};

static void pa_dual_get_write_block_size(size_t write_link_mtu, size_t *write_block_size, void **codec_data) {
    aptx_info_t *aptx_info = *codec_data;
    size_t aptx_frame_size = aptx_info->aptx_frame_size;
    size_t rtp_use_size = aptx_info->is_hd ? sizeof(struct rtp_header) : 0;
    pa_assert(aptx_info);

    /*
     * PCM 32-bit, 2 channel (4 bytes * 2)
     * PCM frames/APTX frames == 4
     * */
    *write_block_size = (write_link_mtu - rtp_use_size) / aptx_frame_size * (4 * 2) * 4;
    aptx_info->block_size = *write_block_size;
};


static void pa_dual_setup_stream(void **codec_data) {
    aptx_info_t *aptx_info = *codec_data;
    pa_assert(aptx_info);
    aptx_info->nb_samples = (int) (aptx_info->block_size / (4 * 2));
    aptx_info->av_codec_ctx->frame_size = (int) (aptx_info->aptx_frame_size * aptx_info->nb_samples / 4);
};

static void pa_dual_free(void **codec_data) {
    aptx_info_t *aptx_info = *codec_data;
    if (!aptx_info)
        return;
    if (aptx_info->av_codec_ctx)
        avcodec_free_context_func(&aptx_info->av_codec_ctx);
    pa_xfree(aptx_info);
    *codec_data = NULL;

};

static size_t _internal_pa_dual_get_capabilities(bool is_hd, void **_capabilities) {

    const size_t cap_size = is_hd ? sizeof(a2dp_aptx_hd_t) : sizeof(a2dp_aptx_t);
    a2dp_aptx_t *capabilities = (a2dp_aptx_t *) pa_xmalloc0(cap_size);

    if (is_hd) {
        capabilities->info = A2DP_SET_VENDOR_ID_CODEC_ID(APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID);
    } else {
        capabilities->info = A2DP_SET_VENDOR_ID_CODEC_ID(APTX_VENDOR_ID, APTX_CODEC_ID);
    }

    capabilities->channel_mode = APTX_CHANNEL_MODE_STEREO;
    capabilities->frequency = APTX_SAMPLING_FREQ_16000 | APTX_SAMPLING_FREQ_32000 | APTX_SAMPLING_FREQ_44100 |
                              APTX_SAMPLING_FREQ_48000;
    *_capabilities = capabilities;

    return cap_size;
};


static size_t
_internal_pa_dual_select_configuration(bool is_hd, const pa_sample_spec default_sample_spec,
                                       const uint8_t *supported_capabilities,
                                       const size_t capabilities_size, void **configuration) {
    a2dp_aptx_t *cap;
    a2dp_aptx_t *config;
    const size_t cap_size = is_hd ? sizeof(a2dp_aptx_hd_t) : sizeof(a2dp_aptx_t);
    pa_a2dp_freq_cap_t aptx_freq_cap, aptx_freq_table[] = {
            {16000U, APTX_SAMPLING_FREQ_16000},
            {32000U, APTX_SAMPLING_FREQ_32000},
            {44100U, APTX_SAMPLING_FREQ_44100},
            {48000U, APTX_SAMPLING_FREQ_48000}
    };

    cap = (a2dp_aptx_t *) supported_capabilities;

    if (capabilities_size != cap_size)
        return 0;

    config = (a2dp_aptx_t *) pa_xmalloc0(cap_size);

    if (is_hd) {
        config->info = A2DP_SET_VENDOR_ID_CODEC_ID(APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID);
    } else {
        config->info = A2DP_SET_VENDOR_ID_CODEC_ID(APTX_VENDOR_ID, APTX_CODEC_ID);
    }

    if (!pa_a2dp_select_cap_frequency(cap->frequency, default_sample_spec, aptx_freq_table,
                                      PA_ELEMENTSOF(aptx_freq_table), &aptx_freq_cap))
        return 0;

    config->frequency = (uint8_t) aptx_freq_cap.cap;

    if (cap->channel_mode & APTX_CHANNEL_MODE_STEREO)
        config->channel_mode = APTX_CHANNEL_MODE_STEREO;
    else {
        pa_log_error("No supported channel modes");
        return 0;
    }

    *configuration = config;
    return cap_size;
};

static void pa_dual_free_capabilities(void **capabilities) {
    if (!capabilities || !*capabilities)
        return;
    pa_xfree(*capabilities);
    *capabilities = NULL;
}

static bool _internal_pa_dual_validate_configuration(bool is_hd, const uint8_t *selected_configuration,
                                                const size_t configuration_size) {
    a2dp_aptx_t *c = (a2dp_aptx_t *) selected_configuration;

    if (configuration_size != (is_hd ? sizeof(a2dp_aptx_hd_t) : sizeof(a2dp_aptx_t))) {
        pa_log_error("APTX configuration array of invalid size");
        return false;
    }

    switch (c->frequency) {
        case APTX_SAMPLING_FREQ_16000:
        case APTX_SAMPLING_FREQ_32000:
        case APTX_SAMPLING_FREQ_44100:
        case APTX_SAMPLING_FREQ_48000:
            break;
        default:
            pa_log_error("Invalid sampling frequency in APTX configuration");
            return false;
    }

    switch (c->channel_mode) {
        case APTX_CHANNEL_MODE_STEREO:
            break;
        default:
            pa_log_error("Invalid channel mode in APTX Configuration");
            return false;
    }
    return true;
};


static bool pa_aptx_decoder_init(void **codec_data) {
    return _internal_pa_dual_decoder_init(false, codec_data);
}

static bool pa_aptx_hd_decoder_init(void **codec_data) {
    return _internal_pa_dual_decoder_init(true, codec_data);
}

static bool
pa_aptx_encoder_init(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb, void **codec_data) {
    return _internal_pa_dual_encoder_init(false, read_cb, free_cb, codec_data);
}

static bool
pa_aptx_hd_encoder_init(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb,
                        void **codec_data) {
    return _internal_pa_dual_encoder_init(true, read_cb, free_cb, codec_data);
}


static size_t pa_aptx_get_capabilities(void **_capabilities) {
    return _internal_pa_dual_get_capabilities(false, _capabilities);
}

static size_t pa_aptx_select_configuration(const pa_sample_spec default_sample_spec,
                                           const uint8_t *supported_capabilities,
                                           const size_t capabilities_size, void **configuration) {
    return _internal_pa_dual_select_configuration(false, default_sample_spec, supported_capabilities, capabilities_size,
                                                  configuration);
}

static bool pa_aptx_validate_configuration(const uint8_t *selected_configuration,
                                      const size_t configuration_size) {
    return _internal_pa_dual_validate_configuration(false, selected_configuration, configuration_size);
}

static size_t pa_aptx_hd_get_capabilities(void **_capabilities) {
    return _internal_pa_dual_get_capabilities(true, _capabilities);
}

static size_t pa_aptx_hd_select_configuration(const pa_sample_spec default_sample_spec,
                                              const uint8_t *supported_capabilities,
                                              const size_t capabilities_size, void **configuration) {
    return _internal_pa_dual_select_configuration(true, default_sample_spec, supported_capabilities, capabilities_size,
                                                  configuration);
}

static bool pa_aptx_hd_validate_configuration(const uint8_t *selected_configuration,
                                         const size_t configuration_size) {
    return _internal_pa_dual_validate_configuration(true, selected_configuration, configuration_size);
}

static pa_a2dp_source_t pa_aptx_source = {
        .encoder_load = pa_aptx_encoder_load,
        .init = pa_aptx_encoder_init,
        .update_user_config = pa_dual_update_user_config,
        .encode = pa_dual_encode,
        .config_transport = pa_dual_config_transport,
        .get_block_size = pa_dual_get_write_block_size,
        .setup_stream = pa_dual_setup_stream,
        .set_tx_length = NULL,
        .decrease_quality = NULL,
        .free = pa_dual_free
};

static pa_a2dp_sink_t pa_aptx_sink = {
        .decoder_load = pa_aptx_decoder_load,
        .init = pa_aptx_decoder_init,
        .update_user_config = pa_dual_update_user_config,
        .config_transport = pa_dual_config_transport,
        .get_block_size = pa_dual_get_read_block_size,
        .setup_stream = pa_dual_setup_stream,
        .decode = pa_dual_decode,
        .free = pa_dual_free
};

const pa_a2dp_codec_t pa_a2dp_aptx = {
        .name = "aptX",
        .codec = A2DP_CODEC_VENDOR,
        .vendor_codec = &A2DP_SET_VENDOR_ID_CODEC_ID(APTX_VENDOR_ID, APTX_CODEC_ID),
        .a2dp_sink = &pa_aptx_sink,
        .a2dp_source = &pa_aptx_source,
        .get_capabilities = pa_aptx_get_capabilities,
        .select_configuration = pa_aptx_select_configuration,
        .free_capabilities = pa_dual_free_capabilities,
        .free_configuration = pa_dual_free_capabilities,
        .validate_configuration = pa_aptx_validate_configuration
};

static pa_a2dp_source_t pa_aptx_hd_source = {
        .encoder_load = pa_aptx_hd_encoder_load,
        .init = pa_aptx_hd_encoder_init,
        .update_user_config = pa_dual_update_user_config,
        .encode = pa_dual_encode,
        .config_transport = pa_dual_config_transport,
        .get_block_size = pa_dual_get_write_block_size,
        .setup_stream = pa_dual_setup_stream,
        .set_tx_length = NULL,
        .decrease_quality = NULL,
        .free = pa_dual_free
};

static pa_a2dp_sink_t pa_aptx_hd_sink = {
        .decoder_load = pa_aptx_hd_decoder_load,
        .init = pa_aptx_hd_decoder_init,
        .update_user_config = pa_dual_update_user_config,
        .config_transport = pa_dual_config_transport,
        .get_block_size = pa_dual_get_read_block_size,
        .setup_stream = pa_dual_setup_stream,
        .decode = pa_dual_decode,
        .free = pa_dual_free
};

const pa_a2dp_codec_t pa_a2dp_aptx_hd = {
        .name = "aptX_HD",
        .codec = A2DP_CODEC_VENDOR,
        .vendor_codec = &A2DP_SET_VENDOR_ID_CODEC_ID(APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID),
        .a2dp_sink = &pa_aptx_hd_sink,
        .a2dp_source = &pa_aptx_hd_source,
        .get_capabilities = pa_aptx_hd_get_capabilities,
        .select_configuration = pa_aptx_hd_select_configuration,
        .free_capabilities = pa_dual_free_capabilities,
        .free_configuration = pa_dual_free_capabilities,
        .validate_configuration = pa_aptx_hd_validate_configuration
};
