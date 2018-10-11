#ifndef fooa2dpcodecapifoo
#define fooa2dpcodecapifoo

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulse/sample.h>
#include <pulse/proplist.h>
#include <pulse/xmalloc.h>
#include <pulsecore/log.h>
#include <pulsecore/macro.h>
#include <pulsecore/once.h>
#include <pulsecore/hashmap.h>

#include "a2dp-codecs.h"
#include "rtp.h"

typedef struct pa_a2dp_codec pa_a2dp_codec_t;
typedef struct pa_a2dp_config pa_a2dp_config_t;

extern const pa_a2dp_codec_t pa_a2dp_sbc;
extern const pa_a2dp_codec_t pa_a2dp_ldac;


/* Implement in module-bluez5-device.c, run from <pa_a2dp_sink_t>.encode */

typedef void (*pa_a2dp_source_read_cb_t)(const void **read_buf, size_t read_buf_size, void *data);

typedef void (*pa_a2dp_source_read_buf_free_cb_t)(const void **read_buf, void *data);


typedef enum pa_a2dp_codec_index {
    PA_A2DP_SINK_MIN,
    PA_A2DP_SINK_SBC,
    PA_A2DP_SINK_MAX,
    PA_A2DP_SOURCE_MIN = PA_A2DP_SINK_MAX,
    PA_A2DP_SOURCE_SBC,
    PA_A2DP_SOURCE_LDAC,
    PA_A2DP_SOURCE_MAX,
    PA_A2DP_CODEC_INDEX_UNAVAILABLE
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

    /* Load decoder syms if it's not loaded; Return true if it's loaded */
    bool (*encoder_load)();

    /* Memory management is pa_a2dp_source's work */
    bool (*init)(pa_a2dp_source_read_cb_t read_cb, pa_a2dp_source_read_buf_free_cb_t free_cb, void **codec_data);

    /* Optional. Update user configurations
     * Note: not transport 'configuration' or 'capabilities' */
    int (*update_user_config)(pa_proplist *user_config, void **codec_data);

    void (*config_transport)(pa_sample_spec default_sample_spec, const void *configuration, size_t configuration_size,
                             pa_sample_spec *sample_spec, void **codec_data);

    void (*get_block_size)(size_t write_link_mtu, size_t *write_block_size, void **codec_data);

    void (*setup_stream)(void **codec_data);

    /* Pass read_cb_data to pa_a2dp_source_read_cb, pa_a2dp_source_read_buf_free_cb */
    size_t (*encode)(uint32_t timestamp, void *write_buf, size_t write_buf_size, size_t *encoded,
                     void *read_cb_data, void **codec_data);

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
    bool (*set_configuration)(const uint8_t *selected_configuration, const size_t configuration_size);

};


typedef struct a_a2dp_freq_cap {
    uint32_t rate;
    uint8_t cap;
} pa_a2dp_freq_cap_t;



/* Utils */

bool pa_a2dp_select_cap_frequency(uint8_t freq_cap, pa_sample_spec default_sample_spec,
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
