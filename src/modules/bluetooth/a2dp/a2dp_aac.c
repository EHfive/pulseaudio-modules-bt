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

#include <fdk-aac/aacenc_lib.h>
#include <fdk-aac/aacdecoder_lib.h>

#include <pulse/xmalloc.h>

#include "a2dp-api.h"

#define streq(a, b) (!strcmp((a),(b)))

#define AAC_DEFAULT_BITRATE 320000u

typedef struct aac_info {
    pa_a2dp_source_read_cb_t read_pcm;
    pa_a2dp_source_read_buf_free_cb_t read_buf_free;

    bool is_a2dp_sink;

    uint16_t seq_num;

    HANDLE_AACDECODER aacdecoder_handle;
    bool aacdecoder_handle_opened;

    HANDLE_AACENCODER aacenc_handle;
    bool aacenc_handle_opened;
    AACENC_InfoStruct aacenc_info;

    uint32_t cfg_bitrate;
    uint32_t bitrate;
    size_t mtu;

    /* Constant Bitrate: 0
     * Variable Bitrate: 1-5 (Only effects when both bluetooth devices have vbr support ) */
    int aac_enc_bitrate_mode;
    uint32_t aac_afterburner;
    pa_sample_format_t force_pa_fmt;

    pa_sample_spec sample_spec;

    size_t read_block_size;
    size_t write_block_size;

} aac_info_t;

static bool pa_aac_decoder_load() {
    /* AAC libs dynamically linked */
    return true;
}

static bool pa_aac_encoder_load() {
    /* AAC libs dynamically linked */
    return true;
}

static bool
pa_aac_decoder_init(void **codec_data) {
    aac_info_t *info = pa_xmalloc0(sizeof(aac_info_t));
    *codec_data = info;
    info->is_a2dp_sink = true;
    return true;
}

static bool
pa_aac_encoder_init(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb, void **codec_data) {
    aac_info_t *info = pa_xmalloc0(sizeof(aac_info_t));
    *codec_data = info;
    info->is_a2dp_sink = false;
    info->read_pcm = read_cb;
    info->read_buf_free = free_cb;
    info->aacenc_handle_opened = false;
    info->aac_enc_bitrate_mode = 5;
    info->aac_afterburner = false;
    info->force_pa_fmt = PA_SAMPLE_INVALID;
    return true;
}

/* KEY                 VALUE    DESC                                      DEFAULT
 * aac_bitrate_mode    [1, 5]   Variable Bitrate (VBR) (encoder)          5
 *                     0        Constant Bitrate (CBR) (encoder)
 *
 * aac_fmt             s16      16-bit signed LE (encoder)                auto
 *                     s32      32-bit signed LE (encoder)
 *                     auto
 *
 * aac_afterburner     <on/off> FDK-AAC afterburner feature (encoder)     off
 */
static int pa_aac_update_user_config(pa_proplist *user_config, void **codec_data) {
    aac_info_t *i = *codec_data;
    const char *aac_bitrate_mode_str, *aac_fmt_str, *aac_afterburner_str;
    int aac_bitrate_mode = 0, ret = 0;
    pa_assert(i);

    aac_bitrate_mode_str = pa_proplist_gets(user_config, "aac_bitrate_mode");
    aac_fmt_str = pa_proplist_gets(user_config, "aac_fmt");
    aac_afterburner_str = pa_proplist_gets(user_config, "aac_afterburner");

    if (aac_bitrate_mode_str) {
        aac_bitrate_mode = atoi(aac_bitrate_mode_str);

        if (aac_bitrate_mode >= 0 && aac_bitrate_mode <= 5) {
            i->aac_enc_bitrate_mode = aac_bitrate_mode;
            ret++;
        } else
            pa_log ("aac_bitrate_mode parameter must in range [0, 5] (found %s)", aac_bitrate_mode_str);
    }

    if (aac_fmt_str) {
        if (streq(aac_fmt_str, "s16")) {
            i->force_pa_fmt = PA_SAMPLE_S16LE;
            ret++;
        } else if (streq(aac_fmt_str, "s32")) {
            i->force_pa_fmt = PA_SAMPLE_S32LE;
            ret++;
        } else if (streq(aac_fmt_str, "auto")) {
            i->force_pa_fmt = PA_SAMPLE_INVALID;
            ret++;
        } else
            pa_log ("aac_fmt parameter must be either s16, s32 or auto (found %s)", aac_fmt_str);
    }

    if (aac_afterburner_str) {
        if (streq("on", aac_afterburner_str)) {
            i->aac_afterburner = 1;
            ret++;
        } else if (streq("off", aac_afterburner_str)) {
            i->aac_afterburner = 0;
            ret++;
        } else
            pa_log ("aac_afterburner parameter must be either on or off (found %s)", aac_afterburner_str);
    }

    return ret;
}

static size_t
pa_aac_decode(const void *read_buf, size_t read_buf_size, void *write_buf, size_t write_buf_size, size_t *_decoded,
              uint32_t *timestamp, void **codec_data) {
    const struct rtp_header *header;
    const UCHAR *p;
    INT_PCM *d;
    UINT to_decode, pkt_size;
    UINT total_written = 0;
    aac_info_t *aac_info = *codec_data;
    pa_assert(aac_info);

    header = read_buf;
    *timestamp = ntohl(header->timestamp);

    p = (UCHAR *) read_buf + sizeof(*header);
    pkt_size = to_decode = (UINT) (read_buf_size - sizeof(*header));

    d = write_buf;

    *_decoded = 0;
    while (PA_LIKELY(to_decode > 0)) {
        CStreamInfo* info;

        AAC_DECODER_ERROR aac_err = aacDecoder_Fill(aac_info->aacdecoder_handle,
                                                    (UCHAR **) &p, &pkt_size, &to_decode);

        if (PA_UNLIKELY(aac_err != AAC_DEC_OK)) {
            pa_log_error("aacDecoder_Fill() error 0x%x", aac_err);
            *_decoded = 0;
            return 0;
        }

        while (true) {
            INT written;
            aac_err = aacDecoder_DecodeFrame(aac_info->aacdecoder_handle, d, (INT) write_buf_size, 0);
            if (PA_UNLIKELY(aac_err == AAC_DEC_NOT_ENOUGH_BITS))
                break;
            if (PA_UNLIKELY(aac_err != AAC_DEC_OK)){
                pa_log_error("aacDecoder_DecodeFrame() error 0x%x", aac_err);
                break;
            }

            info = aacDecoder_GetStreamInfo(aac_info->aacdecoder_handle);
            if(PA_UNLIKELY(!info || info->sampleRate <= 0)) {
                pa_log_error("Invalid stream info");
                break;
            }

            written = info->frameSize * info->numChannels * 2;
            d += written;
            total_written += (UINT) written;
        }
    }

    *_decoded = pkt_size;

    return total_written;
}

static size_t
pa_aac_encode(uint32_t timestamp, void *write_buf, size_t write_buf_size, size_t *_encoded, void *read_cb_data,
              void **codec_data) {
    struct rtp_header *header;
    size_t nbytes;
    uint8_t *d;
    const uint8_t *p;
    int to_write, to_read;
    unsigned frame_count;
    aac_info_t *aac_info = *codec_data;
    const size_t sample_size = pa_sample_size(&aac_info->sample_spec),
            frame_size = pa_frame_size(&aac_info->sample_spec);
    void *in_bufs[1] = {NULL};
    void *out_bufs[1] = {NULL};
    int in_bufferIdentifiers[1] = {IN_AUDIO_DATA};
    int out_bufferIdentifiers[1] = {OUT_BITSTREAM_DATA};
    int in_bufSizes[1] = {(int) (aac_info->aacenc_info.frameLength * frame_size)};
    int out_bufSizes[1];
    int bufElSizes[1] = {(int) sample_size};
    AACENC_BufDesc in_bufDesc = {
            .numBufs = 1,
            .bufs = in_bufs,
            .bufferIdentifiers = in_bufferIdentifiers,
            .bufSizes = in_bufSizes,
            .bufElSizes = bufElSizes
    };
    AACENC_BufDesc out_bufDesc = {
            .numBufs = 1,
            .bufs = out_bufs,
            .bufferIdentifiers = out_bufferIdentifiers,
            .bufSizes = out_bufSizes,
            .bufElSizes = bufElSizes
    };
    AACENC_InArgs in_args = {
            .numAncBytes = 0,
            .numInSamples = aac_info->aacenc_info.frameLength * aac_info->aacenc_info.inputChannels
    };
    AACENC_OutArgs out_args;

    pa_assert(aac_info);

    header = write_buf;

    frame_count = 0;

    aac_info->read_pcm((const void **) &p, (size_t) in_bufSizes[0], read_cb_data);

    in_bufDesc.bufs[0] = (void *) p;
    to_read = in_bufSizes[0];

    d = (uint8_t *) write_buf + sizeof(*header);
    to_write = (int) (write_buf_size - sizeof(*header));
    out_bufDesc.bufs[0] = d;
    out_bufSizes[0] = to_write;


    *_encoded = 0;

    while (PA_UNLIKELY(to_read > 0 && to_write > 0)) {
        size_t encoded;

        AACENC_ERROR aac_err = aacEncEncode(aac_info->aacenc_handle, &in_bufDesc, &out_bufDesc, &in_args, &out_args);

        if (PA_UNLIKELY(aac_err != AACENC_OK)) {
            pa_log_error("AAC encoding error, 0x%x; frame_count:%d, in_bufSizes:%d, out_bufSizes %d, to_read:%d, "
                         "to_write:%d, encoded:%lu",
                         aac_err, frame_count, in_bufSizes[0], out_bufSizes[0], to_read, to_write, *_encoded);
            aac_info->read_buf_free((const void **) &p, read_cb_data);
            *_encoded = 0;
            return 0;
        }

        encoded = out_args.numInSamples * sample_size;
        to_read -= encoded;
        p += encoded;
        *_encoded += encoded;

        to_write -= out_args.numOutBytes;
        d += out_args.numOutBytes;

        frame_count++;
    }

    aac_info->read_buf_free((const void **) &p, read_cb_data);

    memset(write_buf, 0, sizeof(*header));
    header->v = 2;
    header->pt = 96;
    header->sequence_number = htons(aac_info->seq_num++);
    header->timestamp = htonl(timestamp);
    header->ssrc = htonl(1);

    nbytes = d - (uint8_t *) write_buf;

    return nbytes;
}

static void
pa_aac_config_transport(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                        pa_sample_spec *sample_spec, void **codec_data) {
    AACENC_ERROR aac_err;
    aac_info_t *aac_info = *codec_data;
    a2dp_aac_t *config = (a2dp_aac_t *) configuration;
    UINT aot, sample_rate, channels;
    pa_sample_format_t fmt;

    pa_assert(aac_info);
    pa_assert_se(configuration_size == sizeof(*config));

    aac_info->cfg_bitrate = (uint32_t) AAC_GET_BITRATE(*config);
    aac_info->bitrate = PA_MAX(AAC_DEFAULT_BITRATE, aac_info->cfg_bitrate);


    if(aac_info->is_a2dp_sink)
        sample_spec->format = PA_SAMPLE_S16LE;
    else{
        if (aac_info->force_pa_fmt == PA_SAMPLE_INVALID)
            fmt = default_sample_spec.format;
        else
            fmt = aac_info->force_pa_fmt;

        switch (fmt) {
            case PA_SAMPLE_S24LE:
            case PA_SAMPLE_S24BE:
            case PA_SAMPLE_S24_32LE:
            case PA_SAMPLE_S24_32BE:
            case PA_SAMPLE_S32LE:
            case PA_SAMPLE_S32BE:
            case PA_SAMPLE_FLOAT32LE:
            case PA_SAMPLE_FLOAT32BE:
                sample_spec->format = PA_SAMPLE_S32LE;
                break;
            default:
                sample_spec->format = PA_SAMPLE_S16LE;
        }
    }

    switch (config->object_type) {
        case AAC_OBJECT_TYPE_MPEG2_AAC_LC:
            aot = AOT_AAC_LC;
            break;
        case AAC_OBJECT_TYPE_MPEG4_AAC_LC:
            aot = AOT_AAC_LC;
            break;
        case AAC_OBJECT_TYPE_MPEG4_AAC_LTP:
            aot = AOT_AAC_LTP;
            break;
        case AAC_OBJECT_TYPE_MPEG4_AAC_SCA:
            aot = AOT_AAC_SCAL;
            break;
        default:
            pa_log_error("Invalid AAC object type");
            pa_assert_not_reached();
    }

    switch (AAC_GET_FREQUENCY(*config)) {
        case AAC_SAMPLING_FREQ_8000:
            sample_rate = 8000;
            sample_spec->rate = 8000;
            break;
        case AAC_SAMPLING_FREQ_11025:
            sample_rate = 11025;
            sample_spec->rate = 11025;
            break;
        case AAC_SAMPLING_FREQ_12000:
            sample_rate = 12000;
            sample_spec->rate = 12000;
            break;
        case AAC_SAMPLING_FREQ_16000:
            sample_rate = 16000;
            sample_spec->rate = 16000;
            break;
        case AAC_SAMPLING_FREQ_22050:
            sample_rate = 22050;
            sample_spec->rate = 22050;
            break;
        case AAC_SAMPLING_FREQ_24000:
            sample_rate = 24000;
            sample_spec->rate = 24000;
            break;
        case AAC_SAMPLING_FREQ_32000:
            sample_rate = 32000;
            sample_spec->rate = 32000;
            break;
        case AAC_SAMPLING_FREQ_44100:
            sample_rate = 44100;
            sample_spec->rate = 44100;
            break;
        case AAC_SAMPLING_FREQ_48000:
            sample_rate = 48000;
            sample_spec->rate = 48000;
            break;
        case AAC_SAMPLING_FREQ_64000:
            sample_rate = 64000;
            sample_spec->rate = 64000;
            break;
        case AAC_SAMPLING_FREQ_88200:
            sample_rate = 88200;
            sample_spec->rate = 88200;
            break;
        case AAC_SAMPLING_FREQ_96000:
            sample_rate = 96000;
            sample_spec->rate = 96000;
            break;
        default:
            pa_log_error("Invalid AAC frequency");
            pa_assert_not_reached();
    }

    switch (config->channels) {
        case AAC_CHANNELS_1:
            channels = MODE_1;
            sample_spec->channels = 1;
            break;
        case AAC_CHANNELS_2:
            channels = MODE_2;
            sample_spec->channels = 2;
            break;
        default:
            pa_log_error("Invalid AAC channel mode");
            pa_assert_not_reached();
    }

    aac_info->sample_spec = *sample_spec;

    /* AAC SINK */
    if (aac_info->is_a2dp_sink) {
        if (!aac_info->aacdecoder_handle_opened) {
            aac_info->aacdecoder_handle = aacDecoder_Open(TT_MP4_LATM_MCP1, 1);
            aac_info->aacdecoder_handle_opened = true;
        }

        pa_assert_se(AAC_DEC_OK == aacDecoder_SetParam(aac_info->aacdecoder_handle, AAC_PCM_MIN_OUTPUT_CHANNELS,
                                                       sample_spec->channels));
        pa_assert_se(AAC_DEC_OK == aacDecoder_SetParam(aac_info->aacdecoder_handle, AAC_PCM_MAX_OUTPUT_CHANNELS,
                                                       sample_spec->channels));

        return;
    }


    /* AAC SOURCE */

    if (!aac_info->aacenc_handle_opened) {
        aac_err = aacEncOpen(&aac_info->aacenc_handle, 0x07, 2);

        if (aac_err != AACENC_OK) {
            pa_log_error("Cannot open AAC encoder handle: AAC error 0x%x", aac_err);
            pa_assert_not_reached();
        }
        aac_info->aacenc_handle_opened = true;
    }

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_AOT, aot);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_SAMPLERATE, sample_rate);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_CHANNELMODE, channels);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    if (config->vbr) {
        aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_BITRATEMODE,
                                      (UINT) aac_info->aac_enc_bitrate_mode);
        if (aac_err != AACENC_OK)
            pa_assert_not_reached();
    }

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_AUDIOMUXVER, 2);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_SIGNALING_MODE, 1);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_BITRATE, aac_info->bitrate);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_TRANSMUX, TT_MP4_LATM_MCP1);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_HEADER_PERIOD, 1);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_AFTERBURNER, aac_info->aac_afterburner);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncEncode(aac_info->aacenc_handle, NULL, NULL, NULL, NULL);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    pa_assert_se(AACENC_OK == aacEncInfo(aac_info->aacenc_handle, &aac_info->aacenc_info));

    pa_assert(aac_info->aacenc_info.inputChannels == aac_info->sample_spec.channels);

};

static void pa_aac_get_read_block_size(size_t read_link_mtu, size_t *read_block_size, void **codec_data) {
    aac_info_t *aac_info = *codec_data;
    pa_assert(aac_info);

    aac_info->mtu = read_link_mtu;

    /* aacEncoder.pdf Section 3.2.1
     * AAC-LC audio frame contains 1024 PCM samples per channel */
    *read_block_size = 1024 * pa_frame_size(&aac_info->sample_spec);
    aac_info->read_block_size = *read_block_size;
};

static void pa_aac_get_write_block_size(size_t write_link_mtu, size_t *write_block_size, void **codec_data) {
    aac_info_t *aac_info = *codec_data;
    pa_assert(aac_info);

    aac_info->mtu = write_link_mtu;

    /* aacEncoder.pdf section 3.2.1
     * AAC-LC audio frame contains 1024 PCM samples per channel */
    *write_block_size = 1024 * pa_frame_size(&aac_info->sample_spec);
    aac_info->write_block_size = *write_block_size;
};

static void pa_aac_setup_stream(void **codec_data) {
    AACENC_ERROR aac_err;
    aac_info_t *aac_info = *codec_data;
    uint32_t max_bitrate;
    pa_assert(aac_info);

    max_bitrate = (uint32_t) ((8 * (aac_info->mtu - sizeof(struct rtp_header)) * aac_info->sample_spec.rate) / 1024);

    if (aac_info->bitrate > max_bitrate)
        aac_info->bitrate = max_bitrate;

    pa_log_debug("Maximum AAC transmission bitrate: %d bps; Bitrate in use: %d bps", max_bitrate, aac_info->bitrate);

    /* AAC SINK */
    if (aac_info->is_a2dp_sink) {
        return;
    }


    /* AAC SOURCE */

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_BITRATE, aac_info->bitrate);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncoder_SetParam(aac_info->aacenc_handle, AACENC_PEAK_BITRATE, (UINT) max_bitrate);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    aac_err = aacEncEncode(aac_info->aacenc_handle, NULL, NULL, NULL, NULL);
    if (aac_err != AACENC_OK)
        pa_assert_not_reached();

    pa_assert_se(AACENC_OK == aacEncInfo(aac_info->aacenc_handle, &aac_info->aacenc_info));

};

static void pa_aac_free(void **codec_data) {
    aac_info_t *aac_info = *codec_data;
    if (!aac_info)
        return;

    if (aac_info->aacenc_handle_opened)
        aacEncClose(&aac_info->aacenc_handle);

    if (aac_info->aacdecoder_handle_opened)
        aacDecoder_Close(aac_info->aacdecoder_handle);

    pa_xfree(aac_info);
    *codec_data = NULL;

};

static size_t pa_aac_get_capabilities(void **_capabilities) {
    a2dp_aac_t *capabilities = pa_xmalloc0(sizeof(a2dp_aac_t));

    capabilities->object_type = AAC_OBJECT_TYPE_MPEG2_AAC_LC | AAC_OBJECT_TYPE_MPEG4_AAC_LC;
    capabilities->channels = AAC_CHANNELS_1 | AAC_CHANNELS_2;
    AAC_SET_BITRATE(*capabilities, AAC_DEFAULT_BITRATE);
    AAC_SET_FREQUENCY(*capabilities, (AAC_SAMPLING_FREQ_8000 | AAC_SAMPLING_FREQ_11025 | AAC_SAMPLING_FREQ_12000 |
                                      AAC_SAMPLING_FREQ_16000 | AAC_SAMPLING_FREQ_22050 | AAC_SAMPLING_FREQ_24000 |
                                      AAC_SAMPLING_FREQ_32000 | AAC_SAMPLING_FREQ_44100 | AAC_SAMPLING_FREQ_48000 |
                                      AAC_SAMPLING_FREQ_64000 | AAC_SAMPLING_FREQ_88200 | AAC_SAMPLING_FREQ_96000));
    capabilities->vbr = 1;
    *_capabilities = capabilities;

    return sizeof(*capabilities);
};

static size_t
pa_aac_select_configuration(const pa_sample_spec default_sample_spec, const uint8_t *supported_capabilities,
                            const size_t capabilities_size, void **configuration) {
    a2dp_aac_t *cap = (a2dp_aac_t *) supported_capabilities;
    a2dp_aac_t *config = pa_xmalloc0(sizeof(a2dp_aac_t));
    pa_a2dp_freq_cap_t aac_freq_cap, aac_freq_table[] = {
            {8000U,  AAC_SAMPLING_FREQ_8000},
            {11025U, AAC_SAMPLING_FREQ_11025},
            {12000U, AAC_SAMPLING_FREQ_12000},
            {16000U, AAC_SAMPLING_FREQ_16000},
            {22050U, AAC_SAMPLING_FREQ_22050},
            {24000U, AAC_SAMPLING_FREQ_24000},
            {32000U, AAC_SAMPLING_FREQ_32000},
            {44100U, AAC_SAMPLING_FREQ_44100},
            {48000U, AAC_SAMPLING_FREQ_48000},
            {64000U, AAC_SAMPLING_FREQ_64000},
            {88200U, AAC_SAMPLING_FREQ_88200},
            {96000U, AAC_SAMPLING_FREQ_96000}
    };

    if (capabilities_size != sizeof(a2dp_aac_t))
        return 0;

    if (!pa_a2dp_select_cap_frequency(AAC_GET_FREQUENCY(*cap), default_sample_spec, aac_freq_table,
                                      PA_ELEMENTSOF(aac_freq_table), &aac_freq_cap))
        return 0;

    AAC_SET_FREQUENCY(*config, aac_freq_cap.cap);

    AAC_SET_BITRATE(*config, AAC_GET_BITRATE(*cap));

    if (default_sample_spec.channels <= 1) {
        if (cap->channels & AAC_CHANNELS_1)
            config->channels = AAC_CHANNELS_1;
        else if (cap->channels & AAC_CHANNELS_2)
            config->channels = AAC_CHANNELS_2;
        else {
            pa_log_error("No supported channel modes");
            return 0;
        }
    }

    if (default_sample_spec.channels >= 2) {
        if (cap->channels & AAC_CHANNELS_2)
            config->channels = AAC_CHANNELS_2;
        else if (cap->channels & AAC_CHANNELS_1)
            config->channels = AAC_CHANNELS_1;
        else {
            pa_log_error("No supported channel modes");
            return 0;
        }
    }

    if (cap->object_type & AAC_OBJECT_TYPE_MPEG4_AAC_LC)
        config->object_type = AAC_OBJECT_TYPE_MPEG4_AAC_LC;
    else if (cap->object_type & AAC_OBJECT_TYPE_MPEG2_AAC_LC)
        config->object_type = AAC_OBJECT_TYPE_MPEG2_AAC_LC;
    else {
        pa_log_error("No supported aac object type");
        return 0;
    }

    config->vbr = cap->vbr;

    *configuration = config;
    return sizeof(*config);
};

static void pa_aac_free_capabilities(void **capabilities) {
    if (!capabilities || !*capabilities)
        return;
    pa_xfree(*capabilities);
    *capabilities = NULL;
}

static bool pa_aac_validate_configuration(const uint8_t *selected_configuration, const size_t configuration_size) {
    a2dp_aac_t *c = (a2dp_aac_t *) selected_configuration;

    if (configuration_size != sizeof(a2dp_aac_t)) {
        pa_log_error("AAC configuration array of invalid size");
        return false;
    }

    switch (c->object_type) {
        case AAC_OBJECT_TYPE_MPEG2_AAC_LC:
        case AAC_OBJECT_TYPE_MPEG4_AAC_LC:
            break;
        default:
            pa_log_error("Invalid object type in AAC configuration");
            return false;
    }

    switch (AAC_GET_FREQUENCY(*c)) {
        case AAC_SAMPLING_FREQ_8000:
        case AAC_SAMPLING_FREQ_11025:
        case AAC_SAMPLING_FREQ_12000:
        case AAC_SAMPLING_FREQ_16000:
        case AAC_SAMPLING_FREQ_22050:
        case AAC_SAMPLING_FREQ_24000:
        case AAC_SAMPLING_FREQ_32000:
        case AAC_SAMPLING_FREQ_44100:
        case AAC_SAMPLING_FREQ_48000:
        case AAC_SAMPLING_FREQ_64000:
        case AAC_SAMPLING_FREQ_88200:
        case AAC_SAMPLING_FREQ_96000:
            break;
        default:
            pa_log_error("Invalid sampling frequency in AAC configuration");
            return false;
    }

    switch (c->channels) {
        case AAC_CHANNELS_1:
        case AAC_CHANNELS_2:
            break;
        default:
            pa_log_error("Invalid channel mode in AAC Configuration");
            return false;
    }

    return true;
};


static pa_a2dp_source_t pa_aac_source = {
        .encoder_load = pa_aac_encoder_load,
        .init = pa_aac_encoder_init,
        .update_user_config = pa_aac_update_user_config,
        .encode = pa_aac_encode,
        .config_transport=pa_aac_config_transport,
        .get_block_size=pa_aac_get_write_block_size,
        .setup_stream = pa_aac_setup_stream,
        .set_tx_length = NULL,
        .decrease_quality = NULL,
        .free = pa_aac_free
};

static pa_a2dp_sink_t pa_aac_sink = {
        .decoder_load = pa_aac_decoder_load,
        .init = pa_aac_decoder_init,
        .update_user_config = NULL,
        .config_transport=pa_aac_config_transport,
        .get_block_size=pa_aac_get_read_block_size,
        .setup_stream = pa_aac_setup_stream,
        .decode = pa_aac_decode,
        .free = pa_aac_free
};

const pa_a2dp_codec_t pa_a2dp_aac = {
        .name = "AAC",
        .codec = A2DP_CODEC_MPEG24,
        .vendor_codec = NULL,
        .a2dp_sink = &pa_aac_sink,
        .a2dp_source = &pa_aac_source,
        .get_capabilities = pa_aac_get_capabilities,
        .select_configuration = pa_aac_select_configuration,
        .free_capabilities = pa_aac_free_capabilities,
        .free_configuration = pa_aac_free_capabilities,
        .validate_configuration = pa_aac_validate_configuration
};
