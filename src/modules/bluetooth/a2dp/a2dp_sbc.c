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

#include <sbc/sbc.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulse/xmalloc.h>
#include <pulsecore/once.h>

#include "a2dp-api.h"

#define streq(a, b) (!strcmp((a),(b)))

#define BITPOOL_DEC_LIMIT 32
#define BITPOOL_DEC_STEP 5

typedef struct sbc_info {
    pa_a2dp_source_read_cb_t read_pcm;
    pa_a2dp_source_read_buf_free_cb_t read_buf_free;

    bool is_a2dp_sink;

    int channel_mode;
    sbc_t sbc;                           /* Codec data */
    bool sbc_initialized;                /* Keep track if the encoder is initialized */
    size_t codesize, frame_length;       /* SBC Codesize, frame_length. We simply cache those values here */
    uint16_t seq_num;                    /* Cumulative packet sequence */
    uint8_t min_bitpool;
    uint8_t max_bitpool;

    uint8_t forced_min_bitpool;
    uint8_t forced_max_bitpool;
    uint8_t forced_frequency;
    uint8_t forced_channel_mode;
    uint8_t forced_allocation_method;
    uint8_t forced_subbands;
    uint8_t forced_block_length;

    size_t read_block_size;
    size_t write_block_size;

} sbc_info_t;

static bool pa_sbc_decoder_load() {
    /* SBC libs dynamically linked */
    return true;
}

static bool pa_sbc_encoder_load() {
    /* SBC libs dynamically linked */
    return true;
}

static bool
pa_sbc_decoder_init(void **codec_data) {
    sbc_info_t *info = pa_xmalloc0(sizeof(sbc_info_t));
    *codec_data = info;
    info->is_a2dp_sink = true;
    return true;
}

static bool
pa_sbc_encoder_init(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb, void **codec_data) {
    sbc_info_t *info = pa_xmalloc0(sizeof(sbc_info_t));
    *codec_data = info;
    info->is_a2dp_sink = false;
    info->read_pcm = read_cb;
    info->read_buf_free = free_cb;
    return true;
}

static int pa_sbc_update_user_config(pa_proplist *user_config, void **codec_data) {
    int ret = 0;
    sbc_info_t *i = *codec_data;
    const char *sbc_min_bp_str, *sbc_max_bp_str, *sbc_freq_str, *sbc_cmode_str, *sbc_alloc_str, *sbc_sbands_str, *sbc_blen_str;
    uint8_t sbc_min_bitpool = 0, sbc_max_bitpool = 0, sbc_freq = 0, sbc_cmode = 0, sbc_alloc = 0, sbc_sbands = 0, sbc_blen = 0;

    sbc_min_bp_str = pa_proplist_gets(user_config, "sbc_min_bp");
    sbc_max_bp_str = pa_proplist_gets(user_config, "sbc_max_bp");
    sbc_freq_str = pa_proplist_gets(user_config, "sbc_freq");
    sbc_cmode_str = pa_proplist_gets(user_config, "sbc_cmode");
    sbc_alloc_str = pa_proplist_gets(user_config, "sbc_alloc");
    sbc_sbands_str = pa_proplist_gets(user_config, "sbc_sbands");
    sbc_blen_str = pa_proplist_gets(user_config, "sbc_blen");

    if (sbc_min_bp_str && !streq(sbc_min_bp_str, "auto")) {
        sbc_min_bitpool = (uint8_t) atoi(sbc_min_bp_str);
        if (sbc_min_bitpool < SBC_MIN_BITPOOL || sbc_min_bitpool > SBC_MAX_BITPOOL_FORCED) {
            sbc_min_bitpool = 0;
            pa_log_warn("Forced SBC min bitpool value is invalid, ignoring");
        } else {
            pa_log_notice("Using forced SBC min bitpool value: %d", sbc_min_bitpool);
            ret++;
        }
    }

    if (sbc_max_bp_str && !streq(sbc_max_bp_str, "auto")) {
        sbc_max_bitpool = (uint8_t) atoi(sbc_max_bp_str);
        if (sbc_max_bitpool < sbc_min_bitpool || sbc_max_bitpool < SBC_MIN_BITPOOL || sbc_max_bitpool > SBC_MAX_BITPOOL_FORCED) {
            sbc_max_bitpool=0;
            pa_log_warn("Forced SBC max bitpool value is invalid, ignoring");
        } else {
            pa_log_notice("Using forced SBC max bitpool value: %d", sbc_max_bitpool);
            ret++;
        }
    }

    if (sbc_freq_str) {
        if (streq(sbc_freq_str, "16k"))
            sbc_freq = SBC_SAMPLING_FREQ_16000;
        else if (streq(sbc_freq_str, "32k"))
            sbc_freq = SBC_SAMPLING_FREQ_32000;
        else if (streq(sbc_freq_str, "44k"))
            sbc_freq = SBC_SAMPLING_FREQ_44100;
        else if (streq(sbc_freq_str, "48k"))
            sbc_freq = SBC_SAMPLING_FREQ_48000;

        if (sbc_freq > 0) {
            pa_log_notice("Using forced SBC frequency: %s", sbc_freq_str);
            ret++;
        } else if (!streq(sbc_freq_str, "auto"))
            pa_log_warn("Forced SBC frequency value is invalid, ignoring");
    }

    if (sbc_cmode_str) {
        if (streq(sbc_cmode_str, "mono"))
            sbc_cmode = SBC_CHANNEL_MODE_MONO;
        else if (streq(sbc_cmode_str, "dual"))
            sbc_cmode = SBC_CHANNEL_MODE_DUAL_CHANNEL;
        else if (streq(sbc_cmode_str, "stereo"))
            sbc_cmode = SBC_CHANNEL_MODE_STEREO;
        else if (streq(sbc_cmode_str, "joint_stereo"))
            sbc_cmode = SBC_CHANNEL_MODE_JOINT_STEREO;

        if (sbc_cmode > 0) {
            pa_log_notice("Using forced SBC channel-mode: %s", sbc_cmode_str);
            ret++;
        } else if (!streq(sbc_cmode_str, "auto"))
            pa_log_warn("Forced SBC channel-mode value is invalid, ignoring");
    }

    if (sbc_alloc_str) {
        if (streq(sbc_alloc_str, "snr"))
            sbc_alloc = SBC_ALLOCATION_SNR;
        else if (streq(sbc_alloc_str, "loudness"))
            sbc_alloc = SBC_ALLOCATION_LOUDNESS;

        if (sbc_alloc > 0) {
            pa_log_notice("Using forced SBC allocation method: %s", sbc_alloc_str);
            ret++;
        } else if (!streq(sbc_alloc_str, "auto"))
            pa_log_warn("Forced SBC allocation method value is invalid, ignoring");
    }

    if (sbc_sbands_str) {
        if (streq(sbc_sbands_str, "4"))
            sbc_sbands = SBC_SUBBANDS_4;
        else if (streq(sbc_sbands_str, "8"))
            sbc_sbands = SBC_SUBBANDS_8;

        if (sbc_sbands > 0) {
            pa_log_notice("Using forced SBC subbands: %s", sbc_sbands_str);
            ret++;
        } else if (!streq(sbc_sbands_str, "auto"))
            pa_log_warn("Forced SBC subbands value is invalid, ignoring");
    }

    if (sbc_blen_str) {
        if (streq(sbc_blen_str, "4"))
            sbc_blen = SBC_BLOCK_LENGTH_4;
        else if (streq(sbc_blen_str, "8"))
            sbc_blen = SBC_BLOCK_LENGTH_8;
        else if (streq(sbc_blen_str, "12"))
            sbc_blen = SBC_BLOCK_LENGTH_12;
        else if (streq(sbc_blen_str, "16"))
            sbc_blen = SBC_BLOCK_LENGTH_16;

        if (sbc_blen > 0) {
            pa_log_notice("Trying forced SBC block length: %s", sbc_blen_str);
            ret++;
        } else if (!streq(sbc_blen_str, "auto"))
            pa_log_warn("Forced SBC block length value is invalid, ignoring");
    }

    i->forced_min_bitpool = sbc_min_bitpool;
    i->forced_max_bitpool = sbc_max_bitpool;
    i->forced_frequency = sbc_freq;
    i->forced_channel_mode = sbc_cmode;
    i->forced_allocation_method = sbc_alloc;
    i->forced_subbands = sbc_sbands;
    i->forced_block_length = sbc_blen;

    return ret;
}

static size_t
pa_sbc_decode(const void *read_buf, size_t read_buf_size, void *write_buf, size_t write_buf_size, size_t *_decoded,
              uint32_t *timestamp, void **codec_data) {
    const struct rtp_header *header;
    const struct rtp_payload *payload;
    const void *p;
    void *d;
    size_t to_write, to_decode;
    size_t total_written = 0;
    sbc_info_t *sbc_info = *codec_data;
    pa_assert(sbc_info);

    header = read_buf;
    payload = (struct rtp_payload *) ((uint8_t *) read_buf + sizeof(*header));

    *timestamp = ntohl(header->timestamp);

    p = (uint8_t *) read_buf + sizeof(*header) + sizeof(*payload);
    to_decode = read_buf_size - sizeof(*header) - sizeof(*payload);

    d = write_buf;
    to_write = write_buf_size;

    *_decoded = 0;
    while (PA_LIKELY(to_decode > 0)) {
        size_t written;
        ssize_t decoded;

        decoded = sbc_decode(&sbc_info->sbc,
                             p, to_decode,
                             d, to_write,
                             &written);

        if (PA_UNLIKELY(decoded <= 0)) {
            pa_log_error("SBC decoding error (%li)", (long) decoded);
            *_decoded = 0;
            return 0;
        }

        total_written += written;

        /* Reset frame length, it can be changed due to bitpool change */
        sbc_info->frame_length = sbc_get_frame_length(&sbc_info->sbc);

        pa_assert_fp((size_t) decoded <= to_decode);
        pa_assert_fp((size_t) decoded == sbc_info->frame_length);

        pa_assert_fp((size_t) written == sbc_info->codesize);

        *_decoded += decoded;
        p = (const uint8_t *) p + decoded;
        to_decode -= decoded;

        d = (uint8_t *) d + written;
        to_write -= written;
    }

    return total_written;
}

static size_t
pa_sbc_encode(uint32_t timestamp, void *write_buf, size_t write_buf_size, size_t *_encoded, void *read_cb_data,
              void **codec_data) {
    struct rtp_header *header;
    struct rtp_payload *payload;
    size_t nbytes;
    void *d;
    const void *p;
    size_t to_write, to_encode;
    unsigned frame_count;
    sbc_info_t *sbc_info = *codec_data;
    pa_assert(sbc_info);

    header = write_buf;
    payload = (struct rtp_payload *) ((uint8_t *) write_buf + sizeof(*header));

    frame_count = 0;

    /* Try to create a packet of the full MTU */

    sbc_info->read_pcm(&p, (size_t) sbc_info->write_block_size, read_cb_data);

    to_encode = sbc_info->write_block_size;

    d = (uint8_t *) write_buf + sizeof(*header) + sizeof(*payload);
    to_write = write_buf_size - sizeof(*header) - sizeof(*payload);

    *_encoded = 0;
    while (PA_LIKELY(to_encode > 0 && to_write > 0)) {
        ssize_t written;
        ssize_t encoded;

        encoded = sbc_encode(&sbc_info->sbc,
                             p, to_encode,
                             d, to_write,
                             &written);

        if (PA_UNLIKELY(encoded <= 0)) {
            pa_log_error("SBC encoding error (%li)", (long) encoded);
            sbc_info->read_buf_free(&p, read_cb_data);
            *_encoded = 0;
            return 0;
        }

        pa_assert_fp((size_t) encoded <= to_encode);
        pa_assert_fp((size_t) encoded == sbc_info->codesize);

        pa_assert_fp((size_t) written <= to_write);
        pa_assert_fp((size_t) written == sbc_info->frame_length);

        p = (const uint8_t *) p + encoded;
        to_encode -= encoded;
        *_encoded += encoded;

        d = (uint8_t *) d + written;
        to_write -= written;

        frame_count++;
    }

    sbc_info->read_buf_free(&p, read_cb_data);

    pa_assert(to_encode == 0);

    PA_ONCE_BEGIN
                {
                    const char *impl = sbc_get_implementation_info(&sbc_info->sbc);
                    pa_log_debug("Using SBC encoder implementation: %s", impl ? impl : "NULL");
                }
    PA_ONCE_END;

    /* write it to the fifo */
    memset(write_buf, 0, sizeof(*header) + sizeof(*payload));
    header->v = 2;
    header->pt = 96;
    header->sequence_number = htons(sbc_info->seq_num++);
    header->timestamp = htonl(timestamp);
    header->ssrc = htonl(1);
    payload->frame_count = frame_count;

    nbytes = (uint8_t *) d - (uint8_t *) write_buf;

    return nbytes;
}

static void
pa_sbc_config_transport(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                        pa_sample_spec *sample_spec, void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;
    a2dp_sbc_t *config = (a2dp_sbc_t *) configuration;

    pa_assert(sbc_info);
    pa_assert_se(configuration_size == sizeof(*config));

    if (sbc_info->sbc_initialized)
        sbc_reinit(&sbc_info->sbc, 0);
    else
        sbc_init(&sbc_info->sbc, 0);
    sbc_info->sbc_initialized = true;

    sample_spec->format = PA_SAMPLE_S16LE;

    switch (sbc_info->forced_frequency > 0 ? sbc_info->forced_frequency : config->frequency) {
        case SBC_SAMPLING_FREQ_16000:
            sbc_info->sbc.frequency = SBC_FREQ_16000;
            sample_spec->rate = 16000U;
            break;
        case SBC_SAMPLING_FREQ_32000:
            sbc_info->sbc.frequency = SBC_FREQ_32000;
            sample_spec->rate = 32000U;
            break;
        case SBC_SAMPLING_FREQ_44100:
            sbc_info->sbc.frequency = SBC_FREQ_44100;
            sample_spec->rate = 44100U;
            break;
        case SBC_SAMPLING_FREQ_48000:
            sbc_info->sbc.frequency = SBC_FREQ_48000;
            sample_spec->rate = 48000U;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (sbc_info->forced_channel_mode > 0 ? sbc_info->forced_channel_mode : config->channel_mode) {
        case SBC_CHANNEL_MODE_MONO:
            sbc_info->sbc.mode = SBC_MODE_MONO;
            sample_spec->channels = 1;
            break;
        case SBC_CHANNEL_MODE_DUAL_CHANNEL:
            sbc_info->sbc.mode = SBC_MODE_DUAL_CHANNEL;
            sample_spec->channels = 2;
            break;
        case SBC_CHANNEL_MODE_STEREO:
            sbc_info->sbc.mode = SBC_MODE_STEREO;
            sample_spec->channels = 2;
            break;
        case SBC_CHANNEL_MODE_JOINT_STEREO:
            sbc_info->sbc.mode = SBC_MODE_JOINT_STEREO;
            sample_spec->channels = 2;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (sbc_info->forced_allocation_method > 0 ? sbc_info->forced_allocation_method : config->allocation_method) {
        case SBC_ALLOCATION_SNR:
            sbc_info->sbc.allocation = SBC_AM_SNR;
            break;
        case SBC_ALLOCATION_LOUDNESS:
            sbc_info->sbc.allocation = SBC_AM_LOUDNESS;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (sbc_info->forced_subbands > 0 ? sbc_info->forced_subbands : config->subbands) {
        case SBC_SUBBANDS_4:
            sbc_info->sbc.subbands = SBC_SB_4;
            break;
        case SBC_SUBBANDS_8:
            sbc_info->sbc.subbands = SBC_SB_8;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (sbc_info->forced_block_length > 0 ? sbc_info->forced_block_length : config->block_length) {
        case SBC_BLOCK_LENGTH_4:
            sbc_info->sbc.blocks = SBC_BLK_4;
            break;
        case SBC_BLOCK_LENGTH_8:
            sbc_info->sbc.blocks = SBC_BLK_8;
            break;
        case SBC_BLOCK_LENGTH_12:
            sbc_info->sbc.blocks = SBC_BLK_12;
            break;
        case SBC_BLOCK_LENGTH_16:
            sbc_info->sbc.blocks = SBC_BLK_16;
            break;
        default:
            pa_assert_not_reached();
    }

    sbc_info->min_bitpool = sbc_info->forced_min_bitpool ? sbc_info->forced_min_bitpool : config->min_bitpool;
    sbc_info->max_bitpool = sbc_info->forced_max_bitpool ? sbc_info->forced_max_bitpool : config->max_bitpool;
    if (sbc_info->max_bitpool < sbc_info->min_bitpool)
        sbc_info->max_bitpool = sbc_info->min_bitpool;

    /* Set minimum bitpool for source to get the maximum possible block_size */
    sbc_info->sbc.bitpool = sbc_info->is_a2dp_sink ? sbc_info->min_bitpool : sbc_info->max_bitpool;
    sbc_info->codesize = sbc_get_codesize(&sbc_info->sbc);
    sbc_info->frame_length = sbc_get_frame_length(&sbc_info->sbc);

    pa_log_info("SBC parameters: allocation=%u, subbands=%u, blocks=%u, bitpool=%u",
                sbc_info->sbc.allocation, sbc_info->sbc.subbands ? 8 : 4, sbc_info->sbc.blocks, sbc_info->sbc.bitpool);
};

static void pa_sbc_get_read_block_size(size_t read_link_mtu, size_t *read_block_size, void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;
    pa_assert(sbc_info);
    *read_block_size =
            (read_link_mtu - sizeof(struct rtp_header) - sizeof(struct rtp_payload))
            / sbc_info->frame_length * sbc_info->codesize;
    sbc_info->read_block_size = *read_block_size;
};

static void pa_sbc_get_write_block_size(size_t write_link_mtu, size_t *write_block_size, void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;
    pa_assert(sbc_info);
    *write_block_size =
            (write_link_mtu - sizeof(struct rtp_header) - sizeof(struct rtp_payload))
            / sbc_info->frame_length * sbc_info->codesize;
    sbc_info->write_block_size = *write_block_size;
};

static void a2dp_set_bitpool(uint8_t bitpool, void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;

    if (sbc_info->sbc.bitpool == bitpool)
        return;

    if (bitpool > sbc_info->max_bitpool)
        bitpool = sbc_info->max_bitpool;
    else if (bitpool < sbc_info->min_bitpool)
        bitpool = sbc_info->min_bitpool;

    sbc_info->sbc.bitpool = bitpool;

    sbc_info->codesize = sbc_get_codesize(&sbc_info->sbc);
    sbc_info->frame_length = sbc_get_frame_length(&sbc_info->sbc);

    pa_log_debug("Bitpool has changed to %u", sbc_info->sbc.bitpool);
}

static void a2dp_reduce_bitpool(void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;
    uint8_t bitpool;

    /* Check if bitpool is already at its limit */
    if (sbc_info->sbc.bitpool <= BITPOOL_DEC_LIMIT)
        return;

    bitpool = (uint8_t)(sbc_info->sbc.bitpool - BITPOOL_DEC_STEP);

    if (bitpool < BITPOOL_DEC_LIMIT)
        bitpool = BITPOOL_DEC_LIMIT;

    a2dp_set_bitpool(bitpool, codec_data);
}

static void pa_sbc_setup_stream(void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;
    pa_assert(sbc_info);
    if (!sbc_info->is_a2dp_sink)
        a2dp_set_bitpool(sbc_info->max_bitpool, codec_data);
};

static void pa_sbc_free(void **codec_data) {
    sbc_info_t *sbc_info = *codec_data;
    if (!sbc_info)
        return;


    pa_xfree(sbc_info);
    *codec_data = NULL;

};

static size_t pa_sbc_get_capabilities(void **_capabilities) {
    a2dp_sbc_t *capabilities = pa_xmalloc0(sizeof(a2dp_sbc_t));

    capabilities->channel_mode = SBC_CHANNEL_MODE_MONO | SBC_CHANNEL_MODE_DUAL_CHANNEL | SBC_CHANNEL_MODE_STEREO |
                                 SBC_CHANNEL_MODE_JOINT_STEREO;
    capabilities->frequency = SBC_SAMPLING_FREQ_16000 | SBC_SAMPLING_FREQ_32000 | SBC_SAMPLING_FREQ_44100 |
                              SBC_SAMPLING_FREQ_48000;
    capabilities->allocation_method = SBC_ALLOCATION_SNR | SBC_ALLOCATION_LOUDNESS;
    capabilities->subbands = SBC_SUBBANDS_4 | SBC_SUBBANDS_8;
    capabilities->block_length = SBC_BLOCK_LENGTH_4 | SBC_BLOCK_LENGTH_8 | SBC_BLOCK_LENGTH_12 | SBC_BLOCK_LENGTH_16;
    capabilities->min_bitpool = SBC_MIN_BITPOOL;
    capabilities->max_bitpool = SBC_MAX_BITPOOL;

    *_capabilities = capabilities;

    return sizeof(*capabilities);
};

static uint8_t a2dp_default_bitpool(uint8_t freq, uint8_t mode) {
    /* These bitpool values were chosen based on the A2DP spec recommendation */
    switch (freq) {
        case SBC_SAMPLING_FREQ_16000:
        case SBC_SAMPLING_FREQ_32000:
            return 53;

        case SBC_SAMPLING_FREQ_44100:

            switch (mode) {
                case SBC_CHANNEL_MODE_MONO:
                case SBC_CHANNEL_MODE_DUAL_CHANNEL:
                    return 31;

                case SBC_CHANNEL_MODE_STEREO:
                case SBC_CHANNEL_MODE_JOINT_STEREO:
                    return 53;
                default:
                    break;
            }

            pa_log_warn("Invalid channel mode %u", mode);
            return 53;

        case SBC_SAMPLING_FREQ_48000:

            switch (mode) {
                case SBC_CHANNEL_MODE_MONO:
                case SBC_CHANNEL_MODE_DUAL_CHANNEL:
                    return 29;

                case SBC_CHANNEL_MODE_STEREO:
                case SBC_CHANNEL_MODE_JOINT_STEREO:
                    return 51;
                default:
                    break;
            }

            pa_log_warn("Invalid channel mode %u", mode);
            return 51;
        default:
            break;
    }

    pa_log_warn("Invalid sampling freq %u", freq);
    return 53;
}

static size_t
pa_sbc_select_configuration(const pa_sample_spec default_sample_spec, const uint8_t *supported_capabilities,
                            const size_t capabilities_size, void **configuration) {
    a2dp_sbc_t *cap = (a2dp_sbc_t *) supported_capabilities;
    a2dp_sbc_t *config = pa_xmalloc0(sizeof(a2dp_sbc_t));
    pa_a2dp_freq_cap_t sbc_freq_cap, sbc_freq_table[] = {
            {16000U, SBC_SAMPLING_FREQ_16000},
            {32000U, SBC_SAMPLING_FREQ_32000},
            {44100U, SBC_SAMPLING_FREQ_44100},
            {48000U, SBC_SAMPLING_FREQ_48000}
    };

    if (capabilities_size != sizeof(a2dp_sbc_t))
        return 0;

    if (!pa_a2dp_select_cap_frequency(cap->frequency, default_sample_spec, sbc_freq_table,
                                      PA_ELEMENTSOF(sbc_freq_table), &sbc_freq_cap))
        return 0;

    config->frequency = (uint8_t) sbc_freq_cap.cap;

    if (default_sample_spec.channels <= 1) {
        if (cap->channel_mode & SBC_CHANNEL_MODE_MONO)
            config->channel_mode = SBC_CHANNEL_MODE_MONO;
        else if (cap->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO)
            config->channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO;
        else if (cap->channel_mode & SBC_CHANNEL_MODE_STEREO)
            config->channel_mode = SBC_CHANNEL_MODE_STEREO;
        else if (cap->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL)
            config->channel_mode = SBC_CHANNEL_MODE_DUAL_CHANNEL;
        else {
            pa_log_error("No supported channel modes");
            return 0;
        }
    }

    if (default_sample_spec.channels >= 2) {
        if (cap->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO)
            config->channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO;
        else if (cap->channel_mode & SBC_CHANNEL_MODE_STEREO)
            config->channel_mode = SBC_CHANNEL_MODE_STEREO;
        else if (cap->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL)
            config->channel_mode = SBC_CHANNEL_MODE_DUAL_CHANNEL;
        else if (cap->channel_mode & SBC_CHANNEL_MODE_MONO)
            config->channel_mode = SBC_CHANNEL_MODE_MONO;
        else {
            pa_log_error("No supported channel modes");
            return 0;
        }
    }
    if (cap->block_length & SBC_BLOCK_LENGTH_16)
        config->block_length = SBC_BLOCK_LENGTH_16;
    else if (cap->block_length & SBC_BLOCK_LENGTH_12)
        config->block_length = SBC_BLOCK_LENGTH_12;
    else if (cap->block_length & SBC_BLOCK_LENGTH_8)
        config->block_length = SBC_BLOCK_LENGTH_8;
    else if (cap->block_length & SBC_BLOCK_LENGTH_4)
        config->block_length = SBC_BLOCK_LENGTH_4;
    else {
        pa_log_error("No supported block lengths");
        return 0;
    }

    if (cap->subbands & SBC_SUBBANDS_8)
        config->subbands = SBC_SUBBANDS_8;
    else if (cap->subbands & SBC_SUBBANDS_4)
        config->subbands = SBC_SUBBANDS_4;
    else {
        pa_log_error("No supported subbands");
        return 0;
    }

    if (cap->allocation_method & SBC_ALLOCATION_LOUDNESS)
        config->allocation_method = SBC_ALLOCATION_LOUDNESS;
    else if (cap->allocation_method & SBC_ALLOCATION_SNR)
        config->allocation_method = SBC_ALLOCATION_SNR;

    config->min_bitpool = (uint8_t) PA_MAX(SBC_MIN_BITPOOL, cap->min_bitpool);
    config->max_bitpool = (uint8_t) PA_MIN(a2dp_default_bitpool(config->frequency, config->channel_mode),
                                           cap->max_bitpool);

    if (config->min_bitpool > config->max_bitpool)
        return 0;

    *configuration = config;
    return sizeof(*config);
};

static void pa_sbc_free_capabilities(void **capabilities) {
    if (!capabilities || !*capabilities)
        return;
    pa_xfree(*capabilities);
    *capabilities = NULL;
}

static bool pa_sbc_validate_configuration(const uint8_t *selected_configuration, const size_t configuration_size) {
    a2dp_sbc_t *c = (a2dp_sbc_t *) selected_configuration;

    if (configuration_size != sizeof(a2dp_sbc_t)) {
        pa_log_error("SBC configuration array of invalid size");
        return false;
    }

    switch (c->frequency) {
        case SBC_SAMPLING_FREQ_16000:
        case SBC_SAMPLING_FREQ_32000:
        case SBC_SAMPLING_FREQ_44100:
        case SBC_SAMPLING_FREQ_48000:
            break;
        default:
            pa_log_error("Invalid sampling frequency in SBC configuration");
            return false;
    }

    switch (c->channel_mode) {
        case SBC_CHANNEL_MODE_MONO:
        case SBC_CHANNEL_MODE_DUAL_CHANNEL:
        case SBC_CHANNEL_MODE_STEREO:
        case SBC_CHANNEL_MODE_JOINT_STEREO:
            break;
        default:
            pa_log_error("Invalid channel mode in SBC Configuration");
            return false;
    }

    switch (c->allocation_method) {
        case SBC_ALLOCATION_SNR:
        case SBC_ALLOCATION_LOUDNESS:
            break;
        default:
            pa_log_error("Invalid allocation method in SBC configuration");
            return false;
    }

    switch (c->subbands) {
        case SBC_SUBBANDS_4:
        case SBC_SUBBANDS_8:
            break;
        default:
            pa_log_error("Invalid SBC subbands in SBC configuration");
            return false;
    }

    switch (c->block_length) {
        case SBC_BLOCK_LENGTH_4:
        case SBC_BLOCK_LENGTH_8:
        case SBC_BLOCK_LENGTH_12:
        case SBC_BLOCK_LENGTH_16:
            break;
        default:
            pa_log_error("Invalid block length in configuration");
            return false;
    }

    return true;
};


static pa_a2dp_source_t pa_sbc_source = {
        .encoder_load = pa_sbc_encoder_load,
        .init = pa_sbc_encoder_init,
        .update_user_config = pa_sbc_update_user_config,
        .encode = pa_sbc_encode,
        .config_transport=pa_sbc_config_transport,
        .get_block_size=pa_sbc_get_write_block_size,
        .setup_stream = pa_sbc_setup_stream,
        .set_tx_length = NULL,
        .decrease_quality = a2dp_reduce_bitpool,
        .free = pa_sbc_free
};

static pa_a2dp_sink_t pa_sbc_sink = {
        .decoder_load = pa_sbc_decoder_load,
        .init = pa_sbc_decoder_init,
        .update_user_config = pa_sbc_update_user_config,
        .config_transport = pa_sbc_config_transport,
        .get_block_size = pa_sbc_get_read_block_size,
        .setup_stream = pa_sbc_setup_stream,
        .decode = pa_sbc_decode,
        .free = pa_sbc_free
};

const pa_a2dp_codec_t pa_a2dp_sbc = {
        .name = "SBC",
        .codec = A2DP_CODEC_SBC,
        .vendor_codec = NULL,
        .a2dp_sink = &pa_sbc_sink,
        .a2dp_source = &pa_sbc_source,
        .get_capabilities = pa_sbc_get_capabilities,
        .select_configuration = pa_sbc_select_configuration,
        .free_capabilities = pa_sbc_free_capabilities,
        .free_configuration = pa_sbc_free_capabilities,
        .validate_configuration = pa_sbc_validate_configuration
};
