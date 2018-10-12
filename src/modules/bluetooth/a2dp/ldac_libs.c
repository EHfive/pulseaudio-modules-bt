
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include "ldacBT.h"
#include "ldacBT_abr.h"

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulsecore/log.h>

static const char *LDAC_ENCODER_LIB_NAME = "libldacBT_enc.so";

static const char *LDAC_GET_HANDLE_FUNC_NAME = "ldacBT_get_handle";
static const char *LDAC_FREE_HANDLE_FUNC_NAME = "ldacBT_free_handle";
static const char *LDAC_CLOSE_HANDLE_FUNC_NAME = "ldacBT_close_handle";
static const char *LDAC_GET_VERSION_FUNC_NAME = "ldacBT_get_version";
static const char *LDAC_GET_SAMPLING_FREQ_FUNC_NAME = "ldacBT_get_sampling_freq";
static const char *LDAC_GET_BITRATE_FUNC_NAME = "ldacBT_get_bitrate";
static const char *LDAC_INIT_HANDLE_ENCODE_FUNC_NAME = "ldacBT_init_handle_encode";
static const char *LDAC_SET_EQMID_FUNC_NAME = "ldacBT_set_eqmid";
static const char *LDAC_GET_EQMID_FUNC_NAME = "ldacBT_get_eqmid";
static const char *LDAC_ALTER_EQMID_PRIORITY_FUNC_NAME = "ldacBT_alter_eqmid_priority";
static const char *LDAC_ENCODE_FUNC_NAME = "ldacBT_encode";
static const char *LDAC_GET_ERROR_CODE_FUNC_NAME = "ldacBT_get_error_code";


static const char *LDAC_ABR_LIB_NAME = "libldacBT_abr.so";

static const char *LDAC_ABR_GET_HANDLE_FUNC_NAME = "ldac_ABR_get_handle";
static const char *LDAC_ABR_FREE_HANDLE_FUNC_NAME = "ldac_ABR_free_handle";
static const char *LDAC_ABR_INIT_FUNC_NAME = "ldac_ABR_Init";
static const char *LDAC_ABR_SET_THRESHOLDS_FUNC_NAME = "ldac_ABR_set_thresholds";
static const char *LDAC_ABR_PROC_FUNC_NAME = "ldac_ABR_Proc";


typedef HANDLE_LDAC_BT (*ldacBT_get_handle_func_t)(void);

typedef void (*ldacBT_free_handle_func_t)(HANDLE_LDAC_BT hLdacBt);

typedef void (*ldacBT_close_handle_func_t)(HANDLE_LDAC_BT hLdacBt);

typedef int  (*ldacBT_get_version_func_t)(void);

typedef int  (*ldacBT_get_sampling_freq_func_t)(HANDLE_LDAC_BT hLdacBt);

typedef int  (*ldacBT_get_bitrate_func_t)(HANDLE_LDAC_BT hLdacBt);

typedef int  (*ldacBT_init_handle_encode_func_t)(HANDLE_LDAC_BT hLdacBt, int mtu, int eqmid, int cm,
                                                 LDACBT_SMPL_FMT_T fmt, int sf);

typedef int  (*ldacBT_set_eqmid_func_t)(HANDLE_LDAC_BT hLdacBt, int eqmid);

typedef int  (*ldacBT_get_eqmid_func_t)(HANDLE_LDAC_BT hLdacBt);

typedef int  (*ldacBT_alter_eqmid_priority_func_t)(HANDLE_LDAC_BT hLdacBt, int priority);

typedef int  (*ldacBT_encode_func_t)(HANDLE_LDAC_BT hLdacBt, void *p_pcm, int *pcm_used,
                                     unsigned char *p_stream, int *stream_sz, int *frame_num);

typedef int  (*ldacBT_get_error_code_func_t)(HANDLE_LDAC_BT hLdacBt);


typedef HANDLE_LDAC_ABR (*ldac_ABR_get_handle_func_t)(void);

typedef void (*ldac_ABR_free_handle_func_t)(HANDLE_LDAC_ABR hLdacAbr);

typedef int (*ldac_ABR_Init_func_t)(HANDLE_LDAC_ABR hLdacAbr, unsigned int interval_ms);

typedef int (*ldac_ABR_set_thresholds_func_t)(HANDLE_LDAC_ABR hLdacAbr, unsigned int thCritical,
                                              unsigned int thDangerousTrend, unsigned int thSafety4HQSQ);

typedef int (*ldac_ABR_Proc_func_t)(HANDLE_LDAC_BT hLdacBt, HANDLE_LDAC_ABR hLdacAbr,
                                    unsigned int TxQueueDepth, unsigned int flagEnable);

static ldacBT_get_handle_func_t ldacBT_get_handle_func;
static ldacBT_free_handle_func_t ldacBT_free_handle_func;
static ldacBT_close_handle_func_t ldacBT_close_handle_func;
static ldacBT_get_version_func_t ldacBT_get_version_func;
static ldacBT_get_sampling_freq_func_t ldacBT_get_sampling_freq_func;
static ldacBT_get_bitrate_func_t ldacBT_get_bitrate_func;
static ldacBT_init_handle_encode_func_t ldacBT_init_handle_encode_func;
static ldacBT_set_eqmid_func_t ldacBT_set_eqmid_func;
static ldacBT_get_eqmid_func_t ldacBT_get_eqmid_func;
static ldacBT_alter_eqmid_priority_func_t ldacBT_alter_eqmid_priority_func;
static ldacBT_encode_func_t ldacBT_encode_func;
static ldacBT_get_error_code_func_t ldacBT_get_error_code_func;


static ldac_ABR_get_handle_func_t ldac_ABR_get_handle_func;
static ldac_ABR_free_handle_func_t ldac_ABR_free_handle_func;
static ldac_ABR_Init_func_t ldac_ABR_Init_func;
static ldac_ABR_set_thresholds_func_t ldac_ABR_set_thresholds_func;
static ldac_ABR_Proc_func_t ldac_ABR_Proc_func;

static void *ldac_encoder_lib_h = NULL;
static void *ldac_abr_lib_h = NULL;

static bool ldac_abr_loaded = false;


static void *load_func(void *lib_handle, const char *func_name) {
    void *func = dlsym(lib_handle, func_name);
    if (func == NULL) {
        pa_log_error("No function %s in provide library. %s", func_name, dlerror());
        return NULL;
    }
    return func;
}

static bool ldac_abr_load() {
    if (ldac_abr_lib_h)
        return true;
    ldac_abr_lib_h = dlopen(LDAC_ABR_LIB_NAME, RTLD_NOW);
    if (ldac_abr_lib_h == NULL) {
        pa_log_error("Cannot open LDAC abr library: %s. %s", LDAC_ABR_LIB_NAME, dlerror());
        return false;
    }

    ldac_ABR_get_handle_func = (ldac_ABR_get_handle_func_t) load_func(ldac_abr_lib_h,
                                                                      LDAC_ABR_GET_HANDLE_FUNC_NAME);
    if (ldac_ABR_get_handle_func == NULL)
        return false;
    ldac_ABR_free_handle_func = (ldac_ABR_free_handle_func_t) load_func(ldac_abr_lib_h,
                                                                        LDAC_ABR_FREE_HANDLE_FUNC_NAME);
    if (ldac_ABR_free_handle_func == NULL)
        return false;
    ldac_ABR_Init_func = (ldac_ABR_Init_func_t) load_func(ldac_abr_lib_h, LDAC_ABR_INIT_FUNC_NAME);
    if (ldac_ABR_Init_func == NULL)
        return false;
    ldac_ABR_set_thresholds_func = (ldac_ABR_set_thresholds_func_t) load_func(ldac_abr_lib_h,
                                                                              LDAC_ABR_SET_THRESHOLDS_FUNC_NAME);
    if (ldac_ABR_set_thresholds_func == NULL)
        return false;
    ldac_ABR_Proc_func = (ldac_ABR_Proc_func_t) load_func(ldac_abr_lib_h, LDAC_ABR_PROC_FUNC_NAME);
    if (ldac_ABR_Proc_func == NULL)
        return false;
    return true;
}

static void ldac_abr_unload() {
    if (ldac_abr_lib_h != NULL) {
        dlclose(ldac_abr_lib_h);
        ldac_abr_lib_h = NULL;
    }
    ldac_ABR_get_handle_func = NULL;
    ldac_ABR_free_handle_func = NULL;
    ldac_ABR_Init_func = NULL;
    ldac_ABR_set_thresholds_func = NULL;
    ldac_ABR_Proc_func = NULL;
}

static bool _ldac_encoder_load() {
    if (ldac_encoder_lib_h)
        return true;
    ldac_encoder_lib_h = dlopen(LDAC_ENCODER_LIB_NAME, RTLD_NOW);
    if (ldac_encoder_lib_h == NULL) {
        pa_log_error("Cannot open LDAC encoder library: %s. %s", LDAC_ENCODER_LIB_NAME, dlerror());
        return false;
    }

    ldacBT_get_handle_func = (ldacBT_get_handle_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_HANDLE_FUNC_NAME);
    if (ldacBT_get_handle_func == NULL)
        return false;
    ldacBT_free_handle_func = (ldacBT_free_handle_func_t) load_func(ldac_encoder_lib_h, LDAC_FREE_HANDLE_FUNC_NAME);
    if (ldacBT_free_handle_func == NULL)
        return false;
    ldacBT_close_handle_func = (ldacBT_close_handle_func_t) load_func(ldac_encoder_lib_h, LDAC_CLOSE_HANDLE_FUNC_NAME);
    if (ldacBT_close_handle_func == NULL)
        return false;
    ldacBT_get_version_func = (ldacBT_get_version_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_VERSION_FUNC_NAME);
    if (ldacBT_get_version_func == NULL)
        return false;
    ldacBT_get_sampling_freq_func = (ldacBT_get_sampling_freq_func_t) load_func(ldac_encoder_lib_h,
                                                                                LDAC_GET_SAMPLING_FREQ_FUNC_NAME);
    if (ldacBT_get_sampling_freq_func == NULL)
        return false;
    ldacBT_get_bitrate_func = (ldacBT_get_bitrate_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_BITRATE_FUNC_NAME);
    if (ldacBT_get_bitrate_func == NULL)
        return false;
    ldacBT_init_handle_encode_func = (ldacBT_init_handle_encode_func_t) load_func(ldac_encoder_lib_h,
                                                                                  LDAC_INIT_HANDLE_ENCODE_FUNC_NAME);
    if (ldacBT_init_handle_encode_func == NULL)
        return false;
    ldacBT_set_eqmid_func = (ldacBT_set_eqmid_func_t) load_func(ldac_encoder_lib_h, LDAC_SET_EQMID_FUNC_NAME);
    if (ldacBT_set_eqmid_func == NULL)
        return false;
    ldacBT_get_eqmid_func = (ldacBT_get_eqmid_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_EQMID_FUNC_NAME);
    if (ldacBT_get_eqmid_func == NULL)
        return false;
    ldacBT_alter_eqmid_priority_func = (ldacBT_alter_eqmid_priority_func_t) load_func(ldac_encoder_lib_h,
                                                                                      LDAC_ALTER_EQMID_PRIORITY_FUNC_NAME);
    if (ldacBT_alter_eqmid_priority_func == NULL)
        return false;
    ldacBT_encode_func = (ldacBT_encode_func_t) load_func(ldac_encoder_lib_h, LDAC_ENCODE_FUNC_NAME);
    if (ldacBT_encode_func == NULL)
        return false;
    ldacBT_get_error_code_func = (ldacBT_get_error_code_func_t) load_func(ldac_encoder_lib_h,
                                                                          LDAC_GET_ERROR_CODE_FUNC_NAME);
    if (ldacBT_get_error_code_func == NULL)
        return false;

    if (!ldac_abr_load()) {
        pa_log_debug("Cannot load the LDAC ABR library");
        ldac_abr_unload();
        ldac_abr_loaded = false;
    } else
        ldac_abr_loaded = true;
    return true;
}


static void ldac_encoder_unload() {
    if (ldac_encoder_lib_h != NULL) {
        dlclose(ldac_encoder_lib_h);
        ldac_encoder_lib_h = NULL;
    }
    ldacBT_get_handle_func = NULL;
    ldacBT_free_handle_func = NULL;
    ldacBT_close_handle_func = NULL;
    ldacBT_get_version_func = NULL;
    ldacBT_get_sampling_freq_func = NULL;
    ldacBT_get_bitrate_func = NULL;
    ldacBT_init_handle_encode_func = NULL;
    ldacBT_set_eqmid_func = NULL;
    ldacBT_get_eqmid_func = NULL;
    ldacBT_alter_eqmid_priority_func = NULL;
    ldacBT_encode_func = NULL;
    ldacBT_get_error_code_func = NULL;
    ldac_ABR_get_handle_func = NULL;
    ldac_ABR_free_handle_func = NULL;
    ldac_ABR_Init_func = NULL;
    ldac_ABR_set_thresholds_func = NULL;
    ldac_ABR_Proc_func = NULL;
}

static bool ldac_encoder_load() {
    if (!_ldac_encoder_load()) {
        pa_log_debug("Cannot load the LDAC encoder library");
        ldac_encoder_unload();
        return false;
    }
    return true;
}
