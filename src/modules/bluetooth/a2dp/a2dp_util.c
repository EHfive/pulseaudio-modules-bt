
#include <string.h>

#include "../a2dp-api.h"

#define streq(a, b) (!strcmp((a),(b)))

#define A2DP_SOURCE_ENDPOINT "/MediaEndpoint/A2DPSource"
#define A2DP_SINK_ENDPOINT "/MediaEndpoint/A2DPSink"

#define A2DP_SBC_SRC_ENDPOINT A2DP_SOURCE_ENDPOINT "/SBC"
#define A2DP_SBC_SNK_ENDPOINT A2DP_SINK_ENDPOINT "/SBC"

#define A2DP_VENDOR_SRC_ENDPOINT A2DP_SOURCE_ENDPOINT "/VENDOR"
#define A2DP_VENDOR_SNK_ENDPOINT A2DP_SINK_ENDPOINT "/VENDOR"

#define A2DP_APTX_SRC_ENDPOINT A2DP_VENDOR_SRC_ENDPOINT "/APTX"
#define A2DP_APTX_SNK_ENDPOINT A2DP_VENDOR_SNK_ENDPOINT "/APTX"

#define A2DP_APTX_HD_SRC_ENDPOINT A2DP_VENDOR_SRC_ENDPOINT "/APTXHD"
#define A2DP_APTX_HD_SNK_ENDPOINT A2DP_VENDOR_SNK_ENDPOINT "/APTXHD"

#define A2DP_LDAC_SRC_ENDPOINT A2DP_VENDOR_SRC_ENDPOINT "/LDAC"

#define PA_A2DP_PRIORITY_DISABLE 0
#define PA_A2DP_PRIORITY_MIN 1


struct pa_a2dp_config {
    int max_priority;
    pa_hashmap *a2dp_sinks;
    pa_hashmap *a2dp_sources;
    pa_hashmap *active_index_priorities;
    pa_hashmap *ordered_indices;
};

static unsigned int_hash_func(const void *p) {
    return (unsigned) *((const int *) p);
}

static int int_compare_func(const void *a, const void *b) {
    const int x = *((const int *) a);
    const int y = *((const int *) b);
    return x < y ? -1 : (x > y ? 1 : 0);
};


void pa_a2dp_init(pa_a2dp_config_t **a2dp_config) {
    pa_a2dp_config_t *config;
    pa_a2dp_codec_index_t codec_index = PA_A2DP_SINK_MIN;
    const pa_a2dp_codec_t *a2dp_codec;

    config = pa_xmalloc(sizeof(pa_a2dp_config_t));
    *a2dp_config = config;

    config->a2dp_sinks = pa_hashmap_new_full(int_hash_func, int_compare_func, pa_xfree, pa_xfree);
    config->a2dp_sources = pa_hashmap_new_full(int_hash_func, int_compare_func, pa_xfree, pa_xfree);
    config->active_index_priorities = pa_hashmap_new_full(int_hash_func, int_compare_func,
                                                          pa_xfree, pa_xfree);
    config->ordered_indices = NULL;

    config->max_priority = PA_A2DP_PRIORITY_MIN - 1;
    while (++codec_index < PA_A2DP_SINK_MAX) {
        pa_a2dp_codec_index_to_a2dp_codec(codec_index, &a2dp_codec);
        if (!a2dp_codec || !a2dp_codec->a2dp_sink || !a2dp_codec->a2dp_sink->decoder_load())
            continue;
        ++config->max_priority;
        pa_hashmap_put(config->a2dp_sinks, pa_xmemdup(&config->max_priority, sizeof(int)),
                       pa_xmemdup(&codec_index, sizeof(pa_a2dp_codec_index_t)));
        pa_hashmap_put(config->active_index_priorities, pa_xmemdup(&codec_index, sizeof(pa_a2dp_codec_index_t)),
                       pa_xmemdup(&config->max_priority, sizeof(int)));
        a2dp_codec->a2dp_sink->priority = config->max_priority;
    }
    while (++codec_index < PA_A2DP_SOURCE_MAX) {
        pa_a2dp_codec_index_to_a2dp_codec(codec_index, &a2dp_codec);
        if (!a2dp_codec || !a2dp_codec->a2dp_source || !a2dp_codec->a2dp_source->encoder_load())
            continue;
        ++config->max_priority;
        pa_hashmap_put(config->a2dp_sources, pa_xmemdup(&config->max_priority, sizeof(int)),
                       pa_xmemdup(&codec_index, sizeof(pa_a2dp_codec_index_t)));
        pa_hashmap_put(config->active_index_priorities, pa_xmemdup(&codec_index, sizeof(pa_a2dp_codec_index_t)),
                       pa_xmemdup(&config->max_priority, sizeof(int)));
        a2dp_codec->a2dp_source->priority = config->max_priority;
    }
};

void pa_a2dp_set_max_priority(pa_a2dp_codec_index_t codec_index, pa_a2dp_config_t **a2dp_config) {
    const pa_a2dp_codec_t *a2dp_codec;
    pa_a2dp_config_t *config = *a2dp_config;

    pa_a2dp_codec_index_to_a2dp_codec(codec_index, &a2dp_codec);

    if (!a2dp_codec || !pa_hashmap_remove(config->active_index_priorities, &codec_index)) {
        printf("no entry;");
        pa_log_debug("No such codec: %d", codec_index);
        return;
    }

    ++config->max_priority;
    pa_hashmap_put(config->active_index_priorities, pa_xmemdup(&codec_index, sizeof(pa_a2dp_codec_index_t)),
                   pa_xmemdup(&config->max_priority, sizeof(int)));

    if (pa_a2dp_codec_index_is_sink(codec_index))
        a2dp_codec->a2dp_sink->priority = config->max_priority;
    else
        a2dp_codec->a2dp_source->priority = config->max_priority;
};

void pa_a2dp_set_disable(pa_a2dp_codec_index_t codec_index, pa_a2dp_config_t **a2dp_config) {
    const pa_a2dp_codec_t *a2dp_codec;
    pa_a2dp_config_t *config = *a2dp_config;
    pa_a2dp_codec_index_to_a2dp_codec(codec_index, &a2dp_codec);

    if (!a2dp_codec || !pa_hashmap_remove(config->active_index_priorities, &codec_index)) {
        pa_log_debug("No such codec: %d", codec_index);
        return;
    }

    if (pa_a2dp_codec_index_is_sink(codec_index))
        a2dp_codec->a2dp_sink->priority = PA_A2DP_PRIORITY_DISABLE;
    else
        a2dp_codec->a2dp_source->priority = PA_A2DP_PRIORITY_DISABLE;
};

void pa_a2dp_free(pa_a2dp_config_t **a2dp_config) {
    pa_a2dp_config_t *config = *a2dp_config;

    if (!config)
        return;
    if (config->ordered_indices)
        pa_hashmap_free(config->ordered_indices);

    if (config->active_index_priorities)
        pa_hashmap_free(config->active_index_priorities);

    if (config->a2dp_sinks)
        pa_hashmap_free(config->a2dp_sinks);

    if (config->a2dp_sources)
        pa_hashmap_free(config->a2dp_sources);

    pa_xfree(config);
    *a2dp_config = NULL;
}


void pa_a2dp_get_sink_indices(pa_hashmap **sink_indices, pa_a2dp_config_t **a2dp_config) {
    pa_a2dp_config_t *config = *a2dp_config;
    *sink_indices = config->a2dp_sinks;
};

void pa_a2dp_get_source_indices(pa_hashmap **source_indices, pa_a2dp_config_t **a2dp_config) {
    pa_a2dp_config_t *config = *a2dp_config;
    *source_indices = config->a2dp_sources;
};

void pa_a2dp_get_ordered_indices(pa_hashmap **ordered_indices, pa_a2dp_config_t **a2dp_config) {
    void *state;
    pa_a2dp_codec_index_t *index, *indices;
    int *priority, i;
    pa_a2dp_config_t *config = *a2dp_config;

    indices = pa_xmalloc(sizeof(pa_a2dp_codec_index_t) * (config->max_priority + 1));

    for (i = 0; i <= config->max_priority; i++)
        indices[i] = PA_A2DP_CODEC_INDEX_UNAVAILABLE;

    PA_HASHMAP_FOREACH_KV(index, priority, config->active_index_priorities, state) {
        if (*priority <= 0)
            continue;
        indices[*priority] = *index;
    }

    if (config->ordered_indices)
        pa_hashmap_free(config->ordered_indices);
    config->ordered_indices = pa_hashmap_new_full(int_hash_func, int_compare_func, pa_xfree, pa_xfree);

    for (i = config->max_priority; i >= PA_A2DP_PRIORITY_MIN; i--) {
        if (indices[i] == PA_A2DP_CODEC_INDEX_UNAVAILABLE)
            continue;
        priority = pa_xmemdup(&i, sizeof(int));
        index = pa_xmemdup(indices + i, sizeof(pa_a2dp_codec_index_t));
        pa_hashmap_put(config->ordered_indices, priority, index);
    }

    *ordered_indices = config->ordered_indices;
};


void pa_a2dp_codec_index_to_endpoint(pa_a2dp_codec_index_t codec_index, const char **endpoint) {
    switch (codec_index) {
        case PA_A2DP_SINK_SBC:
            *endpoint = A2DP_SBC_SNK_ENDPOINT;
            break;
        case PA_A2DP_SOURCE_SBC:
            *endpoint = A2DP_SBC_SRC_ENDPOINT;
            break;
        case PA_A2DP_SINK_APTX:
            *endpoint = A2DP_APTX_SNK_ENDPOINT;
            break;
        case PA_A2DP_SOURCE_APTX:
            *endpoint = A2DP_APTX_SRC_ENDPOINT;
            break;
        case PA_A2DP_SINK_APTX_HD:
            *endpoint = A2DP_APTX_HD_SNK_ENDPOINT;
            break;
        case PA_A2DP_SOURCE_APTX_HD:
            *endpoint = A2DP_APTX_HD_SRC_ENDPOINT;
            break;
        case PA_A2DP_SOURCE_LDAC:
            *endpoint = A2DP_LDAC_SRC_ENDPOINT;
            break;
        default:
            *endpoint = NULL;
    }
};

void pa_a2dp_endpoint_to_codec_index(const char *endpoint, pa_a2dp_codec_index_t *codec_index) {
    if (streq(endpoint, A2DP_SBC_SNK_ENDPOINT))
        *codec_index = PA_A2DP_SINK_SBC;
    else if (streq(endpoint, A2DP_SBC_SRC_ENDPOINT))
        *codec_index = PA_A2DP_SOURCE_SBC;
    else if (streq(endpoint, A2DP_APTX_SNK_ENDPOINT))
        *codec_index = PA_A2DP_SINK_APTX;
    else if (streq(endpoint, A2DP_APTX_SRC_ENDPOINT))
        *codec_index = PA_A2DP_SOURCE_APTX;
    else if (streq(endpoint, A2DP_APTX_HD_SNK_ENDPOINT))
        *codec_index = PA_A2DP_SINK_APTX_HD;
    else if (streq(endpoint, A2DP_APTX_HD_SRC_ENDPOINT))
        *codec_index = PA_A2DP_SOURCE_APTX_HD;
    else if (streq(endpoint, A2DP_LDAC_SRC_ENDPOINT))
        *codec_index = PA_A2DP_SOURCE_LDAC;
    else
        *codec_index = PA_A2DP_CODEC_INDEX_UNAVAILABLE;
};

void pa_a2dp_codec_index_to_a2dp_codec(pa_a2dp_codec_index_t codec_index, const pa_a2dp_codec_t **a2dp_codec) {
    switch (codec_index) {
        case PA_A2DP_SINK_SBC:
        case PA_A2DP_SOURCE_SBC:
            *a2dp_codec = &pa_a2dp_sbc;
            break;
        case PA_A2DP_SINK_APTX:
        case PA_A2DP_SOURCE_APTX:
            *a2dp_codec = &pa_a2dp_aptx;
            break;
        case PA_A2DP_SINK_APTX_HD:
        case PA_A2DP_SOURCE_APTX_HD:
            *a2dp_codec = &pa_a2dp_aptx_hd;
            break;
        case PA_A2DP_SOURCE_LDAC:
            *a2dp_codec = &pa_a2dp_ldac;
            break;
        default:
            *a2dp_codec = NULL;
    }
};

void pa_a2dp_a2dp_codec_to_codec_index(const pa_a2dp_codec_t *a2dp_codec, bool is_a2dp_sink,
                                       pa_a2dp_codec_index_t *codec_index) {
    if (!a2dp_codec) {
        *codec_index = PA_A2DP_CODEC_INDEX_UNAVAILABLE;
        return;
    }
    switch (a2dp_codec->codec) {
        case A2DP_CODEC_SBC:
            *codec_index = is_a2dp_sink ? PA_A2DP_SINK_SBC : PA_A2DP_SOURCE_SBC;
            return;
        case A2DP_CODEC_VENDOR:
            if (!a2dp_codec->vendor_codec) {
                *codec_index = PA_A2DP_CODEC_INDEX_UNAVAILABLE;
                return;
            } else if (a2dp_codec->vendor_codec->vendor_id == APTX_VENDOR_ID &&
                      a2dp_codec->vendor_codec->codec_id == APTX_CODEC_ID) {
                *codec_index = is_a2dp_sink ? PA_A2DP_SINK_APTX : PA_A2DP_SOURCE_APTX;
                return;
            } else if (a2dp_codec->vendor_codec->vendor_id == APTX_HD_VENDOR_ID &&
                       a2dp_codec->vendor_codec->codec_id == APTX_HD_CODEC_ID) {
                *codec_index = is_a2dp_sink ? PA_A2DP_SINK_APTX_HD : PA_A2DP_SOURCE_APTX_HD;
                return;
            } else if (a2dp_codec->vendor_codec->vendor_id == LDAC_VENDOR_ID &&
                a2dp_codec->vendor_codec->codec_id == LDAC_CODEC_ID) {
                *codec_index = is_a2dp_sink ? PA_A2DP_CODEC_INDEX_UNAVAILABLE : PA_A2DP_SOURCE_LDAC;
                return;
            }
            *codec_index = PA_A2DP_CODEC_INDEX_UNAVAILABLE;
            break;
        default:
            *codec_index = PA_A2DP_CODEC_INDEX_UNAVAILABLE;
    }
};

void
pa_a2dp_get_a2dp_codec(uint8_t codec, const a2dp_vendor_codec_t *vendor_codec, const pa_a2dp_codec_t **a2dp_codec) {
    switch (codec) {
        case A2DP_CODEC_SBC:
            *a2dp_codec = &pa_a2dp_sbc;
            return;
        case A2DP_CODEC_VENDOR:
            if (!vendor_codec) {
                *a2dp_codec = NULL;
                pa_assert_not_reached();
            } else if (vendor_codec->vendor_id == APTX_VENDOR_ID && vendor_codec->codec_id == APTX_CODEC_ID) {
                *a2dp_codec = &pa_a2dp_aptx;
                return;
            } else if (vendor_codec->vendor_id == APTX_HD_VENDOR_ID && vendor_codec->codec_id == APTX_HD_CODEC_ID) {
                *a2dp_codec = &pa_a2dp_aptx_hd;
                return;
            } else if (vendor_codec->vendor_id == LDAC_VENDOR_ID && vendor_codec->codec_id == LDAC_CODEC_ID) {
                *a2dp_codec = &pa_a2dp_ldac;
                return;
            }
            *a2dp_codec = NULL;
            break;
        default:
            *a2dp_codec = NULL;
    }
};

bool pa_a2dp_codec_index_is_sink(pa_a2dp_codec_index_t codec_index) {
    if (codec_index > PA_A2DP_SINK_MIN && codec_index < PA_A2DP_SINK_MAX)
        return true;
    return false;
};

bool pa_a2dp_codec_index_is_source(pa_a2dp_codec_index_t codec_index) {
    if (codec_index > PA_A2DP_SOURCE_MIN && codec_index < PA_A2DP_SOURCE_MAX)
        return true;
    return false;
};

bool
pa_a2dp_select_cap_frequency(uint32_t freq_cap, pa_sample_spec default_sample_spec,
                             const pa_a2dp_freq_cap_t *freq_cap_table,
                             size_t n, pa_a2dp_freq_cap_t *result) {
    int i;
    /* Find the lowest freq that is at least as high as the requested sampling rate */
    for (i = 0; (unsigned) i < n; i++)
        if (freq_cap_table[i].rate >= default_sample_spec.rate && (freq_cap & freq_cap_table[i].cap)) {
            *result = freq_cap_table[i];
            break;
        }

    if ((unsigned) i == n) {
        for (--i; i >= 0; i--) {
            if (freq_cap & freq_cap_table[i].cap) {
                *result = freq_cap_table[i];
                break;
            }
        }

        if (i < 0) {
            pa_log_error("Not suitable sample rate");
            return false;
        }
    }
    pa_assert((unsigned) i < n);
    return true;
};
