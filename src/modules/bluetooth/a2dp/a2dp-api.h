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

#ifndef fooa2dpcodecapifoo
#define fooa2dpcodecapifoo

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulse/sample.h>
#include <pulse/proplist.h>
#include <pulsecore/hashmap.h>

#include "a2dp-codecs.h"
#include "rtp.h"

typedef struct pa_a2dp_codec pa_a2dp_codec_t;
typedef struct pa_a2dp_config pa_a2dp_config_t;

extern const pa_a2dp_codec_t pa_a2dp_sbc;
extern const pa_a2dp_codec_t pa_a2dp_aac;
extern const pa_a2dp_codec_t pa_a2dp_aptx;
extern const pa_a2dp_codec_t pa_a2dp_aptx_hd;
extern const pa_a2dp_codec_t pa_a2dp_ldac;

#define PTR_PA_A2DP_SBC (&pa_a2dp_sbc)
#ifdef PA_A2DP_CODEC_AAC_FDK
    #define PTR_PA_A2DP_AAC (&pa_a2dp_aac)
#else
    #define PTR_PA_A2DP_AAC (NULL)
#endif

#ifdef PA_A2DP_CODEC_APTX_FF
    #define PTR_PA_A2DP_APTX (&pa_a2dp_aptx)
#else
    #define PTR_PA_A2DP_APTX (NULL)
#endif

#ifdef PA_A2DP_CODEC_APTX_HD_FF
    #define PTR_PA_A2DP_APTX_HD (&pa_a2dp_aptx_hd)
#else
    #define PTR_PA_A2DP_APTX_HD (NULL)
#endif

#ifdef PA_A2DP_CODEC_LDAC
    #define PTR_PA_A2DP_LDAC (&pa_a2dp_ldac)
#else
    #define PTR_PA_A2DP_LDAC (NULL)
#endif

/* Implement in module-bluez5-device.c, run from <pa_a2dp_sink_t>.encode */

typedef void (*pa_a2dp_source_read_cb_t)(const void **read_buf, size_t read_buf_size, void *data);

typedef void (*pa_a2dp_source_read_buf_free_cb_t)(const void **read_buf, void *data);


typedef enum pa_a2dp_codec_index {
    PA_A2DP_SINK_MIN,
    PA_A2DP_SINK_SBC,
#ifdef PA_A2DP_CODEC_AAC_FDK
    PA_A2DP_SINK_AAC,
#endif
#ifdef PA_A2DP_CODEC_APTX_FF
    PA_A2DP_SINK_APTX,
#endif
#ifdef PA_A2DP_CODEC_APTX_HD_FF
    PA_A2DP_SINK_APTX_HD,
#endif
    PA_A2DP_SINK_MAX,
    PA_A2DP_SOURCE_MIN = PA_A2DP_SINK_MAX,
    PA_A2DP_SOURCE_SBC,
#ifdef PA_A2DP_CODEC_AAC_FDK
    PA_A2DP_SOURCE_AAC,
#endif
#ifdef PA_A2DP_CODEC_APTX_FF
    PA_A2DP_SOURCE_APTX,
#endif
#ifdef PA_A2DP_CODEC_APTX_HD_FF
    PA_A2DP_SOURCE_APTX_HD,
#endif
#ifdef PA_A2DP_CODEC_LDAC
    PA_A2DP_SOURCE_LDAC,
#endif
    PA_A2DP_SOURCE_MAX,
    PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#ifndef PA_A2DP_CODEC_AAC_FDK
    PA_A2DP_SINK_AAC = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
#ifndef PA_A2DP_CODEC_APTX_FF
    PA_A2DP_SINK_APTX = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
#ifndef PA_A2DP_CODEC_APTX_HD_FF
    PA_A2DP_SINK_APTX_HD = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
#ifndef PA_A2DP_CODEC_AAC_FDK
    PA_A2DP_SOURCE_AAC = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
#ifndef PA_A2DP_CODEC_APTX_FF
    PA_A2DP_SOURCE_APTX = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
#ifndef PA_A2DP_CODEC_APTX_HD_FF
    PA_A2DP_SOURCE_APTX_HD = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
#ifndef PA_A2DP_CODEC_LDAC
    PA_A2DP_SOURCE_LDAC = PA_A2DP_CODEC_INDEX_UNAVAILABLE,
#endif
} pa_a2dp_codec_index_t;

typedef struct pa_a2dp_sink {
    int priority;

    /* Load decoder syms if it's not loaded; Return true if it's loaded */
    bool (*decoder_load)();

    /* Memory management is pa_a2dp_sink's work */
    bool (*init)(void **codec_data);

    /* Optional. Update user configurations
     * Note: not transport 'configuration' or 'capabilities' */
    int (*update_user_config)(pa_proplist *user_config, void **codec_data);

    void (*config_transport)(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                             pa_sample_spec *sample_spec, void **codec_data);

    void (*get_block_size)(size_t read_link_mtu, size_t *read_block_size, void **codec_data);

    void (*setup_stream)(void **codec_data);

    size_t
    (*decode)(const void *read_buf, size_t read_buf_size, void *write_buf, size_t write_buf_size, size_t *decoded,
              uint32_t *timestamp, void **codec_data);

    void (*free)(void **codec_data);
} pa_a2dp_sink_t;


typedef struct pa_a2dp_source {
    int priority;

    /* Load encoder syms if it's not loaded; Return true if it's loaded */
    bool (*encoder_load)();

    /* Memory management is pa_a2dp_source's work */
    bool (*init)(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb, void **codec_data);

    /* Optional. Update user configurations
     * Note: not transport 'configuration' or 'capabilities' */
    int (*update_user_config)(pa_proplist *user_config, void **codec_data);

    void (*config_transport)(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                             pa_sample_spec *sample_spec, void **codec_data);

    void (*get_block_size)(size_t write_link_mtu, size_t *write_block_size, void **codec_data);

    size_t (*handle_update_buffer_size)(void **codec_data);

    void (*setup_stream)(void **codec_data);

    /* Pass read_cb_data to pa_a2dp_source_read_cb, pa_a2dp_source_read_buf_free_cb */
    size_t (*encode)(uint32_t timestamp, void *write_buf, size_t write_buf_size, size_t *encoded,
                     void *read_cb_data, void **codec_data);

    /* Optional, return size of bytes to skip */
    size_t (*handle_skipping)(size_t bytes_to_send, void **codec_data);

    /* Optional */
    void (*set_tx_length)(size_t len, void **codec_data);

    /* Optional */
    void (*decrease_quality)(void **codec_data);

    void (*free)(void **codec_data);
} pa_a2dp_source_t;


struct pa_a2dp_codec {
    const char *name;
    uint8_t codec;
    const a2dp_vendor_codec_t *vendor_codec;
    pa_a2dp_sink_t *a2dp_sink;
    pa_a2dp_source_t *a2dp_source;

    /* Memory management is pa_a2dp_codec's work */
    size_t (*get_capabilities)(void **capabilities);

    void (*free_capabilities)(void **capabilities);

    size_t (*select_configuration)(const pa_sample_spec default_sample_spec, const uint8_t *supported_capabilities,
                                   const size_t capabilities_size, void **configuration);

    void (*free_configuration)(void **configuration);

    /* Return if configuration valid */
    bool (*validate_configuration)(const uint8_t *selected_configuration, const size_t configuration_size);

};


typedef struct pa_a2dp_freq_cap {
    uint32_t rate;
    uint32_t cap;
} pa_a2dp_freq_cap_t;



/* Utils */

bool pa_a2dp_select_cap_frequency(uint32_t freq_cap, pa_sample_spec default_sample_spec,
                                  const pa_a2dp_freq_cap_t *freq_cap_table,
                                  size_t n, pa_a2dp_freq_cap_t *result);

void pa_a2dp_init(pa_a2dp_config_t **a2dp_config);

void pa_a2dp_set_max_priority(pa_a2dp_codec_index_t codec_index, pa_a2dp_config_t **a2dp_config);

void pa_a2dp_set_disable(pa_a2dp_codec_index_t codec_index, pa_a2dp_config_t **a2dp_config);

void pa_a2dp_free(pa_a2dp_config_t **a2dp_config);


void pa_a2dp_get_sink_indices(pa_hashmap **sink_indices, pa_a2dp_config_t **a2dp_config);

void pa_a2dp_get_source_indices(pa_hashmap **source_indices, pa_a2dp_config_t **a2dp_config);

void pa_a2dp_get_ordered_indices(pa_hashmap **ordered_indices, pa_a2dp_config_t **a2dp_config);


void pa_a2dp_codec_index_to_endpoint(pa_a2dp_codec_index_t codec_index, const char **endpoint);

void pa_a2dp_endpoint_to_codec_index(const char *endpoint, pa_a2dp_codec_index_t *codec_index);

void pa_a2dp_codec_index_to_a2dp_codec(pa_a2dp_codec_index_t codec_index, const pa_a2dp_codec_t **a2dp_codec);

void
pa_a2dp_a2dp_codec_to_codec_index(const pa_a2dp_codec_t *a2dp_codec, bool is_sink, pa_a2dp_codec_index_t *codec_index);

void pa_a2dp_get_a2dp_codec(uint8_t codec, const a2dp_vendor_codec_t *vendor_codec, const pa_a2dp_codec_t **a2dp_codec);

bool pa_a2dp_codec_index_is_sink(pa_a2dp_codec_index_t codec_index);

bool pa_a2dp_codec_index_is_source(pa_a2dp_codec_index_t codec_index);


#endif
