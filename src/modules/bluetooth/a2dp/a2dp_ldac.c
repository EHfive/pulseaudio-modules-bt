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
#include <errno.h>

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulse/xmalloc.h>
#include <pulsecore/once.h>
#include <pulsecore/sample-util.h>

#include <ldacBT.h>
#include <ldacBT_abr.h>

#include "a2dp-api.h"

#include "ldac_libs.h"

#define streq(a, b) (!strcmp((a),(b)))

#define LDAC_ABR_THRESHOLD_CRITICAL 5
#define LDAC_ABR_THRESHOLD_DANGEROUSTREND 3
#define LDAC_ABR_THRESHOLD_SAFETY_FOR_HQSQ 1


#define LDAC_ABR_INTERVAL_MS 5


typedef struct ldac_info {
    HANDLE_LDAC_BT hLdacBt;
    HANDLE_LDAC_ABR hLdacAbr;

    pa_a2dp_source_read_cb_t read_pcm;
    pa_a2dp_source_read_buf_free_cb_t read_buf_free;

    int eqmid;
    bool enable_abr;
    int channel_mode;
    pa_sample_format_t force_pa_fmt;
    LDACBT_SMPL_FMT_T pcm_fmt;
    unsigned int abr_t1;
    unsigned int abr_t2;
    unsigned int abr_t3;
    uint32_t pcm_frequency;

    uint16_t pcm_lsu;
    size_t ldac_frame_size;
    size_t pcm_read_size;
    size_t q_write_block_size;
    pa_sample_spec sample_spec;

    uint16_t seq_num;
    uint32_t layer_specific;
    uint32_t written;
    size_t tx_length;

    size_t interval_bytes;
    size_t read_bytes;

    uint8_t buf_index;
    void *buf;

    size_t mtu;

} ldac_info_t;

static bool pa_ldac_encoder_load() {
    return ldac_encoder_load();
}

static bool
pa_ldac_encoder_init(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb, void **codec_data) {
    ldac_info_t *info = pa_xmalloc0(sizeof(ldac_info_t));
    *codec_data = info;
    info->read_pcm = read_cb;
    info->read_buf_free = free_cb;
    info->eqmid = LDACBT_EQMID_HQ;
    if(is_ldac_abr_loaded())
        info->enable_abr = true;
    info->force_pa_fmt = PA_SAMPLE_INVALID;

    info->abr_t1 = LDAC_ABR_THRESHOLD_SAFETY_FOR_HQSQ;
    info->abr_t2 = LDAC_ABR_THRESHOLD_DANGEROUSTREND;
    info->abr_t3 = LDAC_ABR_THRESHOLD_CRITICAL;

    return true;
}

static int pa_ldac_update_user_config(pa_proplist *user_config, void **codec_data) {
    ldac_info_t *i = *codec_data;
    const char *ldac_eqmid_str, *ldac_fmt_str, *abr_t1_str, *abr_t2_str, *abr_t3_str;
    unsigned int abr_t1, abr_t2, abr_t3;
    int ret = 0;
    ldac_eqmid_str = pa_proplist_gets(user_config, "ldac_eqmid");
    ldac_fmt_str = pa_proplist_gets(user_config, "ldac_fmt");
    abr_t1_str = pa_proplist_gets(user_config, "ldac_abr_t1");
    abr_t2_str = pa_proplist_gets(user_config, "ldac_abr_t2");
    abr_t3_str = pa_proplist_gets(user_config, "ldac_abr_t3");

    pa_log_debug("LDAC ABR library loaded: %s",is_ldac_abr_loaded()?"true":"false");

    if (ldac_eqmid_str) {
        if (streq(ldac_eqmid_str, "hq")) {
            i->eqmid = LDACBT_EQMID_HQ;
            i->enable_abr = false;
            ret++;
        } else if (streq(ldac_eqmid_str, "sq")) {
            i->eqmid = LDACBT_EQMID_SQ;
            i->enable_abr = false;
            ret++;
        } else if (streq(ldac_eqmid_str, "mq")) {
            i->eqmid = LDACBT_EQMID_MQ;
            i->enable_abr = false;
            ret++;
        } else if (streq(ldac_eqmid_str, "auto") ||
                   streq(ldac_eqmid_str, "abr")) {
            i->eqmid = LDACBT_EQMID_HQ;
            if(is_ldac_abr_loaded())
                i->enable_abr = true;
            ret++;
        } else {
            pa_log("ldac_eqmid parameter must be either hq, sq, mq, or auto/abr (found %s)", ldac_eqmid_str);
        }
    }

    if (ldac_fmt_str) {
        if (streq(ldac_fmt_str, "s16")) {
            i->force_pa_fmt = PA_SAMPLE_S16LE;
            ret++;
        } else if (streq(ldac_fmt_str, "s24")) {
            i->force_pa_fmt = PA_SAMPLE_S24LE;
            ret++;
        } else if (streq(ldac_fmt_str, "s32")) {
            i->force_pa_fmt = PA_SAMPLE_S32LE;
            ret++;
        } else if (streq(ldac_fmt_str, "f32")) {
            i->force_pa_fmt = PA_SAMPLE_FLOAT32LE;
            ret++;
        } else if (streq(ldac_fmt_str, "auto")) {
            i->force_pa_fmt = PA_SAMPLE_INVALID;
            ret++;
        } else {
            pa_log("ldac_fmt parameter must be either s16, s24, s32, f32 or auto (found %s)", ldac_fmt_str);
        }
    }

    abr_t1 = abr_t1_str ? (unsigned int) atoi(abr_t1_str) : i->abr_t1;
    abr_t2 = abr_t2_str ? (unsigned int) atoi(abr_t2_str) : i->abr_t2;
    abr_t3 = abr_t3_str ? (unsigned int) atoi(abr_t3_str) : i->abr_t3;

    if (0 < abr_t1 && abr_t1 <= abr_t2 && abr_t2 <= abr_t3) {
        i->abr_t1 = abr_t1;
        i->abr_t2 = abr_t2;
        i->abr_t3 = abr_t3;
        ret += i->abr_t1 != abr_t1;
        ret += i->abr_t2 != abr_t2;
        ret += i->abr_t3 != abr_t3;
    } else
        pa_log("ldac_abr_t1,2,3 parameter(s) invalid, ensure 0 < ldac_abr_t1 <= ldac_abr_t2 <= ldac_abr_t3");

    return ret;
}

static size_t
pa_ldac_encode(uint32_t timestamp, void *write_buf, size_t write_buf_size, size_t *_encoded, void *read_cb_data,
               void **codec_data) {
    struct rtp_header *header;
    struct rtp_payload *payload;
    size_t nbytes;
    void *d;
    const void *p;
    size_t to_write, to_encode, ldac_enc_read;
    unsigned frame_count;
    ldac_info_t *ldac_info = *codec_data;
    pa_assert(ldac_info);
    pa_assert(ldac_info->hLdacBt);

    if(PA_UNLIKELY(ldac_info->buf != write_buf && ldac_info->buf)){
        int ret;
        ldac_info->buf_index = 0;
        ldacBT_close_handle_func(ldac_info->hLdacBt);
        ret = ldacBT_init_handle_encode_func(ldac_info->hLdacBt,
                                             (int) ldac_info->mtu,
                                             ldac_info->eqmid,
                                             ldac_info->channel_mode,
                                             ldac_info->pcm_fmt,
                                             ldac_info->pcm_frequency);
        if (ret != 0) {
            pa_log_warn("Failed to init ldacBT handle");
            return 0;
        }
    }

    if (!ldac_info->buf_index && ldac_info->hLdacAbr && ldac_info->enable_abr &&
        ldac_info->read_bytes >= ldac_info->interval_bytes) {
        ldac_ABR_Proc_func(ldac_info->hLdacBt, ldac_info->hLdacAbr,
                           (unsigned int) (ldac_info->tx_length / ldac_info->q_write_block_size),
                           (unsigned int) ldac_info->enable_abr);
        ldac_info->tx_length = 0;
        ldac_info->read_bytes = 0;
    }

    ldac_info->buf = write_buf;


    ldac_enc_read = (pa_frame_size(&ldac_info->sample_spec) * LDACBT_ENC_LSU);

    header = write_buf;
    payload = (struct rtp_payload *) ((uint8_t *) write_buf + sizeof(*header));

    frame_count = 0;

    to_encode = ldac_info->q_write_block_size;

    d = (uint8_t *) write_buf + sizeof(*header) + sizeof(*payload) + ldac_info->buf_index;
    to_write = write_buf_size - sizeof(*header) - sizeof(*payload) - ldac_info->buf_index;

    *_encoded = 0;
    while (PA_LIKELY(to_encode > 0 && to_write > 0 && frame_count == 0)) {
        int written;
        int encoded;
        int ldac_frame_num;
        int ret_code;
        ldac_info->read_pcm(&p, ldac_enc_read, read_cb_data);

        ret_code = ldacBT_encode_func(ldac_info->hLdacBt, (void *) p, &encoded, (uint8_t *) d, &written, &ldac_frame_num);

        ldac_info->read_buf_free(&p, read_cb_data);

        if (PA_UNLIKELY(ret_code < 0)) {
            int err;
            pa_log_error("LDAC encoding error, written:%d encoded:%d ldac_frame_num:%d", written, encoded,
                         ldac_frame_num);
            err = ldacBT_get_error_code_func(ldac_info->hLdacBt);
            pa_log_error("LDACBT_API_ERR:%d  LDACBT_HANDLE_ERR:%d  LDACBT_BLOCK_ERR:%d", LDACBT_API_ERR(err),
                         LDACBT_HANDLE_ERR(err), LDACBT_BLOCK_ERR(err));
            *_encoded = 0;
            return 0;
        }

        pa_assert_fp(encoded == (int) ldac_enc_read);
        pa_assert_fp(written <= (int) to_write);

        *_encoded += encoded;
        to_encode -= encoded;

        d = (uint8_t *) d + written;
        ldac_info->buf_index += written;
        to_write -= written;

        frame_count += ldac_frame_num;

    }

    ldac_info->read_bytes += *_encoded;


    PA_ONCE_BEGIN
                {
                    const int v = ldacBT_get_version_func();
                    pa_log_notice("Using LDAC library: version: %x.%02x.%02x",
                                  v >> 16,
                                  (v >> 8) & 0x0ff,
                                  v & 0x0ff
                    );
                }
    PA_ONCE_END;

    if(frame_count == 0)
        return -EINPROGRESS;
    ldac_info->buf_index = 0;

    /* write it to the fifo */
    memset(write_buf, 0, sizeof(*header) + sizeof(*payload));
    header->v = 2;
    header->pt = 96;
    header->sequence_number = htons(ldac_info->seq_num++);
    header->timestamp = htonl(timestamp);
    header->ssrc = htonl(1);
    payload->frame_count = frame_count;
    ldac_info->layer_specific += frame_count;

    nbytes = (uint8_t *) d - (uint8_t *) write_buf;

    ldac_info->written += nbytes - sizeof(*header) - sizeof(*payload);

    return nbytes;
}

static void
pa_ldac_config_transport(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                         pa_sample_spec *sample_spec, void **codec_data) {
    ldac_info_t *ldac_info = *codec_data;
    a2dp_ldac_t *config = (a2dp_ldac_t *) configuration;
    pa_sample_format_t fmt;
    pa_assert(ldac_info);
    pa_assert_se(configuration_size == sizeof(*config));

    ldac_info->hLdacBt = NULL;
    ldac_info->hLdacAbr = NULL;

    if (ldac_info->force_pa_fmt == PA_SAMPLE_INVALID)
        fmt = default_sample_spec.format;
    else
        fmt = ldac_info->force_pa_fmt;

    switch (fmt) {
        case PA_SAMPLE_FLOAT32LE:
        case PA_SAMPLE_FLOAT32BE:
            ldac_info->pcm_fmt = LDACBT_SMPL_FMT_F32;
            sample_spec->format = PA_SAMPLE_FLOAT32LE;
            break;
        case PA_SAMPLE_S32LE:
        case PA_SAMPLE_S32BE:
            ldac_info->pcm_fmt = LDACBT_SMPL_FMT_S32;
            sample_spec->format = PA_SAMPLE_S32LE;
            break;
        case PA_SAMPLE_S24LE:
        case PA_SAMPLE_S24BE:
        case PA_SAMPLE_S24_32LE:
        case PA_SAMPLE_S24_32BE:
            ldac_info->pcm_fmt = LDACBT_SMPL_FMT_S24;
            sample_spec->format = PA_SAMPLE_S24LE;
            break;
        default:
            ldac_info->pcm_fmt = LDACBT_SMPL_FMT_S16;
            sample_spec->format = PA_SAMPLE_S16LE;
    }


    switch (config->frequency) {
        case LDACBT_SAMPLING_FREQ_044100:
            ldac_info->pcm_frequency = 44100U;
            sample_spec->rate = 44100U;
            break;
        case LDACBT_SAMPLING_FREQ_048000:
            ldac_info->pcm_frequency = 48000U;
            sample_spec->rate = 48000U;
            break;
        case LDACBT_SAMPLING_FREQ_088200:
            ldac_info->pcm_frequency = 88200U;
            sample_spec->rate = 88200U;
            break;
        case LDACBT_SAMPLING_FREQ_096000:
            ldac_info->pcm_frequency = 96000U;
            sample_spec->rate = 96000U;
            break;
        case LDACBT_SAMPLING_FREQ_176400:
            ldac_info->pcm_frequency = 176400U;
            sample_spec->rate = 176400U;
            break;
        case LDACBT_SAMPLING_FREQ_192000:
            ldac_info->pcm_frequency = 192000U;
            sample_spec->rate = 192000U;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (config->channel_mode) {
        case LDACBT_CHANNEL_MODE_MONO:
            ldac_info->channel_mode = LDACBT_CHANNEL_MODE_MONO;
            sample_spec->channels = 1;
            break;
        case LDACBT_CHANNEL_MODE_DUAL_CHANNEL:
            ldac_info->channel_mode = LDACBT_CHANNEL_MODE_DUAL_CHANNEL;
            sample_spec->channels = 2;
            break;
        case LDACBT_CHANNEL_MODE_STEREO:
            ldac_info->channel_mode = LDACBT_CHANNEL_MODE_STEREO;
            sample_spec->channels = 2;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (ldac_info->pcm_frequency) {
        case 44100:
        case 48000:
            ldac_info->pcm_lsu = 128;
            break;
        case 88200:
        case 96000:
            ldac_info->pcm_lsu = 256;
            break;
        case 176400:
        case 192000:
            ldac_info->pcm_lsu = 512;
            break;
        default:
            pa_assert_not_reached();
    }

    switch (ldac_info->eqmid) {
        case LDACBT_EQMID_HQ:
            ldac_info->ldac_frame_size = 330;
            break;
        case LDACBT_EQMID_SQ:
            ldac_info->ldac_frame_size = 220;
            break;
        case LDACBT_EQMID_MQ:
            ldac_info->ldac_frame_size = 110;
            break;
        default:
            pa_assert_not_reached();
    }

    ldac_info->sample_spec = *sample_spec;
    ldac_info->pcm_read_size = (ldac_info->pcm_lsu * pa_frame_size(&ldac_info->sample_spec));
    ldac_info->interval_bytes = pa_usec_to_bytes(LDAC_ABR_INTERVAL_MS * 1000, &ldac_info->sample_spec);

};

static size_t pa_ldac_handle_update_buffer_size(void **codec_data) {
    ldac_info_t *ldac_info = *codec_data;
    pa_assert(ldac_info);
    return ldac_info->q_write_block_size * ldac_info->abr_t3;
}

static void pa_ldac_get_block_size(size_t write_link_mtu, size_t *write_block_size, void **codec_data) {
    ldac_info_t *ldac_info = *codec_data;
    pa_assert(ldac_info);

    ldac_info->mtu = write_link_mtu;

    ldac_info->q_write_block_size = ((write_link_mtu - sizeof(struct rtp_header) - sizeof(struct rtp_payload))
                                     / ldac_info->ldac_frame_size * ldac_info->pcm_read_size);
    *write_block_size = ldac_info->q_write_block_size;
};


static void pa_ldac_setup_stream(void **codec_data) {
    int ret;
    ldac_info_t *ldac_info = *codec_data;
    pa_assert(ldac_info);

    ldac_info->layer_specific = 0;
    ldac_info->written = 0;
    ldac_info->buf = NULL;
    ldac_info->buf_index = 0;
    if (ldac_info->hLdacBt)
        ldacBT_free_handle_func(ldac_info->hLdacBt);
    ldac_info->hLdacBt = ldacBT_get_handle_func();


    ret = ldacBT_init_handle_encode_func(ldac_info->hLdacBt,
                                    (int) ldac_info->mtu,
                                    ldac_info->eqmid,
                                    ldac_info->channel_mode,
                                    ldac_info->pcm_fmt,
                                    ldac_info->pcm_frequency);
    if (ret != 0) {
        pa_log_warn("Failed to init ldacBT handle");
        goto fail;
    }

    if (!is_ldac_abr_loaded())
        return;

    if (ldac_info->hLdacAbr)
        ldac_ABR_free_handle_func(ldac_info->hLdacAbr);
    ldac_info->hLdacAbr = ldac_ABR_get_handle_func();

    ret = ldac_ABR_Init_func(ldac_info->hLdacAbr, LDAC_ABR_INTERVAL_MS);
    if (ret != 0) {
        pa_log_warn("Failed to init ldacBT_ABR handle");
        goto fail1;
    }

    ldac_ABR_set_thresholds_func(ldac_info->hLdacAbr, ldac_info->abr_t3, ldac_info->abr_t2, ldac_info->abr_t1);
    return;

fail:
    ldacBT_free_handle_func(ldac_info->hLdacBt);
    ldac_info->hLdacBt = NULL;
    if (!is_ldac_abr_loaded())
        return;
fail1:
    ldac_ABR_free_handle_func(ldac_info->hLdacAbr);
    ldac_info->hLdacAbr = NULL;
    ldac_info->enable_abr = false;
};

static size_t pa_ldac_handle_skipping(size_t bytes_to_send, void **codec_data) {
    ldac_info_t *info = *codec_data;
    size_t skip_bytes;
    pa_assert(info);
    skip_bytes = pa_frame_align(bytes_to_send - ((bytes_to_send / 2) % info->q_write_block_size),
                                &info->sample_spec);
    if(!info->enable_abr){
        if(bytes_to_send > 2 * info->q_write_block_size)
            return skip_bytes;
    } else if (bytes_to_send / info->q_write_block_size > info->abr_t3)
        return skip_bytes;
    return 0;
}

static void pa_ldac_set_tx_length(size_t len, void **codec_data) {
    ldac_info_t *ldac_info = *codec_data;
    pa_assert(ldac_info);
    ldac_info->tx_length += PA_MAX(ldac_info->tx_length, len);
};

static void pa_ldac_free(void **codec_data) {
    ldac_info_t *ldac_info = *codec_data;
    if (!ldac_info)
        return;

    if (ldac_info->hLdacBt)
        ldacBT_free_handle_func(ldac_info->hLdacBt);

    if (ldac_info->hLdacAbr && is_ldac_abr_loaded())
        ldac_ABR_free_handle_func(ldac_info->hLdacAbr);

    pa_xfree(ldac_info);
    *codec_data = NULL;

};

static size_t pa_ldac_get_capabilities(void **_capabilities) {
    a2dp_ldac_t *capabilities = pa_xmalloc0(sizeof(a2dp_ldac_t));

    capabilities->info = A2DP_SET_VENDOR_ID_CODEC_ID(LDAC_VENDOR_ID, LDAC_CODEC_ID);
    capabilities->frequency = LDACBT_SAMPLING_FREQ_044100 | LDACBT_SAMPLING_FREQ_048000 |
                              LDACBT_SAMPLING_FREQ_088200 | LDACBT_SAMPLING_FREQ_096000;
    capabilities->channel_mode = LDACBT_CHANNEL_MODE_MONO | LDACBT_CHANNEL_MODE_DUAL_CHANNEL |
                                 LDACBT_CHANNEL_MODE_STEREO;
    *_capabilities = capabilities;

    return sizeof(*capabilities);
};

static size_t
pa_ldac_select_configuration(const pa_sample_spec default_sample_spec, const uint8_t *supported_capabilities,
                             const size_t capabilities_size, void **configuration) {
    a2dp_ldac_t *cap = (a2dp_ldac_t *) supported_capabilities;
    a2dp_ldac_t *config = pa_xmalloc0(sizeof(a2dp_ldac_t));
    pa_a2dp_freq_cap_t ldac_freq_cap, ldac_freq_table[] = {
            {44100U,  LDACBT_SAMPLING_FREQ_044100},
            {48000U,  LDACBT_SAMPLING_FREQ_048000},
            {88200U,  LDACBT_SAMPLING_FREQ_088200},
            {96000U,  LDACBT_SAMPLING_FREQ_096000}
    };

    if (capabilities_size != sizeof(a2dp_ldac_t))
        return 0;

    config->info = A2DP_SET_VENDOR_ID_CODEC_ID(LDAC_VENDOR_ID, LDAC_CODEC_ID);

    if (!pa_a2dp_select_cap_frequency(cap->frequency, default_sample_spec, ldac_freq_table,
                                      PA_ELEMENTSOF(ldac_freq_table), &ldac_freq_cap))
        return 0;

    config->frequency = (uint8_t) ldac_freq_cap.cap;

    if (default_sample_spec.channels <= 1) {
        if (cap->channel_mode & LDACBT_CHANNEL_MODE_MONO)
            config->channel_mode = LDACBT_CHANNEL_MODE_MONO;
        else if (cap->channel_mode & LDACBT_CHANNEL_MODE_STEREO)
            config->channel_mode = LDACBT_CHANNEL_MODE_STEREO;
        else if (cap->channel_mode & LDACBT_CHANNEL_MODE_DUAL_CHANNEL)
            config->channel_mode = LDACBT_CHANNEL_MODE_DUAL_CHANNEL;
        else {
            pa_log_error("No supported channel modes");
            return 0;
        }
    }

    if (default_sample_spec.channels >= 2) {
        if (cap->channel_mode & LDACBT_CHANNEL_MODE_STEREO)
            config->channel_mode = LDACBT_CHANNEL_MODE_STEREO;
        else if (cap->channel_mode & LDACBT_CHANNEL_MODE_DUAL_CHANNEL)
            config->channel_mode = LDACBT_CHANNEL_MODE_DUAL_CHANNEL;
        else if (cap->channel_mode & LDACBT_CHANNEL_MODE_MONO)
            config->channel_mode = LDACBT_CHANNEL_MODE_MONO;
        else {
            pa_log_error("No supported channel modes");
            return 0;
        }
    }
    *configuration = config;
    return sizeof(*config);
};

static void pa_ldac_free_capabilities(void **capabilities) {
    if (!capabilities || !*capabilities)
        return;
    pa_xfree(*capabilities);
    *capabilities = NULL;
}

static bool pa_ldac_validate_configuration(const uint8_t *selected_configuration, const size_t configuration_size) {
    a2dp_ldac_t *c = (a2dp_ldac_t *) selected_configuration;

    if (configuration_size != sizeof(a2dp_ldac_t)) {
        pa_log_error("LDAC configuration array of invalid size");
        return false;
    }

    switch (c->frequency) {
        case LDACBT_SAMPLING_FREQ_044100:
        case LDACBT_SAMPLING_FREQ_048000:
        case LDACBT_SAMPLING_FREQ_088200:
        case LDACBT_SAMPLING_FREQ_096000:
        case LDACBT_SAMPLING_FREQ_176400:
        case LDACBT_SAMPLING_FREQ_192000:
            break;
        default:
            pa_log_error("Invalid sampling frequency in LDAC configuration");
            return false;
    }

    switch (c->channel_mode) {
        case LDACBT_CHANNEL_MODE_STEREO:
        case LDACBT_CHANNEL_MODE_DUAL_CHANNEL:
        case LDACBT_CHANNEL_MODE_MONO:
            break;
        default:
            pa_log_error("Invalid channel mode in LDAC Configuration");
            return false;
    }

    return true;
};


static pa_a2dp_source_t pa_ldac_source = {
        .encoder_load = pa_ldac_encoder_load,
        .init = pa_ldac_encoder_init,
        .update_user_config = pa_ldac_update_user_config,
        .encode = pa_ldac_encode,
        .config_transport = pa_ldac_config_transport,
        .handle_update_buffer_size = pa_ldac_handle_update_buffer_size,
        .get_block_size = pa_ldac_get_block_size,
        .setup_stream = pa_ldac_setup_stream,
        .handle_skipping = pa_ldac_handle_skipping,
        .set_tx_length = pa_ldac_set_tx_length,
        .decrease_quality = NULL,
        .free = pa_ldac_free
};

const pa_a2dp_codec_t pa_a2dp_ldac = {
        .name = "LDAC",
        .codec = A2DP_CODEC_VENDOR,
        .vendor_codec = &A2DP_SET_VENDOR_ID_CODEC_ID(LDAC_VENDOR_ID, LDAC_CODEC_ID),
        .a2dp_sink = NULL,
        .a2dp_source = &pa_ldac_source,
        .get_capabilities = pa_ldac_get_capabilities,
        .select_configuration = pa_ldac_select_configuration,
        .free_capabilities = pa_ldac_free_capabilities,
        .free_configuration = pa_ldac_free_capabilities,
        .validate_configuration = pa_ldac_validate_configuration
};
