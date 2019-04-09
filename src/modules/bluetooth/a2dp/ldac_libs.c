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

#ifdef HAVE_CONFIG_H

#include <config.h>

#endif

#include <pulsecore/log.h>

#include "ldac_libs.h"

static const char *LDAC_ENCODER_LIB_NAMES[] = {
        "libldacBT_enc.so.2",
        "libldacBT_enc.so"
};

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


static const char *LDAC_ABR_LIB_NAMES[] = {
        "libldacBT_abr.so.2",
        "libldacBT_abr.so"
};

static const char *LDAC_ABR_GET_HANDLE_FUNC_NAME = "ldac_ABR_get_handle";
static const char *LDAC_ABR_FREE_HANDLE_FUNC_NAME = "ldac_ABR_free_handle";
static const char *LDAC_ABR_INIT_FUNC_NAME = "ldac_ABR_Init";
static const char *LDAC_ABR_SET_THRESHOLDS_FUNC_NAME = "ldac_ABR_set_thresholds";
static const char *LDAC_ABR_PROC_FUNC_NAME = "ldac_ABR_Proc";


ldacBT_get_handle_func_t ldacBT_get_handle_func;
ldacBT_free_handle_func_t ldacBT_free_handle_func;
ldacBT_close_handle_func_t ldacBT_close_handle_func;
ldacBT_get_version_func_t ldacBT_get_version_func;
ldacBT_get_sampling_freq_func_t ldacBT_get_sampling_freq_func;
ldacBT_get_bitrate_func_t ldacBT_get_bitrate_func;
ldacBT_init_handle_encode_func_t ldacBT_init_handle_encode_func;
ldacBT_set_eqmid_func_t ldacBT_set_eqmid_func;
ldacBT_get_eqmid_func_t ldacBT_get_eqmid_func;
ldacBT_alter_eqmid_priority_func_t ldacBT_alter_eqmid_priority_func;
ldacBT_encode_func_t ldacBT_encode_func;
ldacBT_get_error_code_func_t ldacBT_get_error_code_func;


ldac_ABR_get_handle_func_t ldac_ABR_get_handle_func;
ldac_ABR_free_handle_func_t ldac_ABR_free_handle_func;
ldac_ABR_Init_func_t ldac_ABR_Init_func;
ldac_ABR_set_thresholds_func_t ldac_ABR_set_thresholds_func;
ldac_ABR_Proc_func_t ldac_ABR_Proc_func;

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

static bool ldac_abr_load() {
    if (ldac_abr_lib_h)
        return true;
    for (int i = 0; i < PA_ELEMENTSOF(LDAC_ABR_LIB_NAMES); ++i) {
        ldac_abr_unload();
        ldac_abr_lib_h = dlopen(LDAC_ABR_LIB_NAMES[i], RTLD_NOW);
        if (ldac_abr_lib_h == NULL) {
            pa_log_warn("Cannot open LDAC abr library: %s. %s", LDAC_ABR_LIB_NAMES[i], dlerror());
            continue;
        }
        ldac_ABR_get_handle_func = (ldac_ABR_get_handle_func_t) load_func(ldac_abr_lib_h,
                                                                          LDAC_ABR_GET_HANDLE_FUNC_NAME);
        if (ldac_ABR_get_handle_func == NULL)
            continue;
        ldac_ABR_free_handle_func = (ldac_ABR_free_handle_func_t) load_func(ldac_abr_lib_h,
                                                                            LDAC_ABR_FREE_HANDLE_FUNC_NAME);
        if (ldac_ABR_free_handle_func == NULL)
            continue;
        ldac_ABR_Init_func = (ldac_ABR_Init_func_t) load_func(ldac_abr_lib_h, LDAC_ABR_INIT_FUNC_NAME);
        if (ldac_ABR_Init_func == NULL)
            continue;
        ldac_ABR_set_thresholds_func = (ldac_ABR_set_thresholds_func_t) load_func(ldac_abr_lib_h,
                                                                                  LDAC_ABR_SET_THRESHOLDS_FUNC_NAME);
        if (ldac_ABR_set_thresholds_func == NULL)
            continue;
        ldac_ABR_Proc_func = (ldac_ABR_Proc_func_t) load_func(ldac_abr_lib_h, LDAC_ABR_PROC_FUNC_NAME);
        if (ldac_ABR_Proc_func == NULL)
            continue;
        return true;
    }
    return false;
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

static bool _ldac_encoder_load() {
    if (ldac_encoder_lib_h)
        return true;
    for (int i = 0; i < PA_ELEMENTSOF(LDAC_ENCODER_LIB_NAMES); ++i) {
        ldac_encoder_unload();
        ldac_encoder_lib_h = dlopen(LDAC_ENCODER_LIB_NAMES[i], RTLD_NOW);
        if (ldac_encoder_lib_h == NULL) {
            pa_log_warn("Cannot open LDAC encoder library: %s. %s", LDAC_ENCODER_LIB_NAMES[i], dlerror());
            continue;
        }
        ldacBT_get_handle_func = (ldacBT_get_handle_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_HANDLE_FUNC_NAME);
        if (ldacBT_get_handle_func == NULL)
            continue;
        ldacBT_free_handle_func = (ldacBT_free_handle_func_t) load_func(ldac_encoder_lib_h, LDAC_FREE_HANDLE_FUNC_NAME);
        if (ldacBT_free_handle_func == NULL)
            continue;
        ldacBT_close_handle_func = (ldacBT_close_handle_func_t) load_func(ldac_encoder_lib_h,
                                                                          LDAC_CLOSE_HANDLE_FUNC_NAME);
        if (ldacBT_close_handle_func == NULL)
            continue;
        ldacBT_get_version_func = (ldacBT_get_version_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_VERSION_FUNC_NAME);
        if (ldacBT_get_version_func == NULL)
            continue;
        ldacBT_get_sampling_freq_func = (ldacBT_get_sampling_freq_func_t) load_func(ldac_encoder_lib_h,
                                                                                    LDAC_GET_SAMPLING_FREQ_FUNC_NAME);
        if (ldacBT_get_sampling_freq_func == NULL)
            continue;
        ldacBT_get_bitrate_func = (ldacBT_get_bitrate_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_BITRATE_FUNC_NAME);
        if (ldacBT_get_bitrate_func == NULL)
            continue;
        ldacBT_init_handle_encode_func = (ldacBT_init_handle_encode_func_t) load_func(ldac_encoder_lib_h,
                                                                                      LDAC_INIT_HANDLE_ENCODE_FUNC_NAME);
        if (ldacBT_init_handle_encode_func == NULL)
            continue;
        ldacBT_set_eqmid_func = (ldacBT_set_eqmid_func_t) load_func(ldac_encoder_lib_h, LDAC_SET_EQMID_FUNC_NAME);
        if (ldacBT_set_eqmid_func == NULL)
            continue;
        ldacBT_get_eqmid_func = (ldacBT_get_eqmid_func_t) load_func(ldac_encoder_lib_h, LDAC_GET_EQMID_FUNC_NAME);
        if (ldacBT_get_eqmid_func == NULL)
            continue;
        ldacBT_alter_eqmid_priority_func = (ldacBT_alter_eqmid_priority_func_t) load_func(ldac_encoder_lib_h,
                                                                                          LDAC_ALTER_EQMID_PRIORITY_FUNC_NAME);
        if (ldacBT_alter_eqmid_priority_func == NULL)
            continue;
        ldacBT_encode_func = (ldacBT_encode_func_t) load_func(ldac_encoder_lib_h, LDAC_ENCODE_FUNC_NAME);
        if (ldacBT_encode_func == NULL)
            continue;
        ldacBT_get_error_code_func = (ldacBT_get_error_code_func_t) load_func(ldac_encoder_lib_h,
                                                                              LDAC_GET_ERROR_CODE_FUNC_NAME);
        if (ldacBT_get_error_code_func == NULL)
            continue;
        if (!ldac_abr_load()) {
            pa_log_debug("Cannot load the LDAC ABR library");
            ldac_abr_unload();
            ldac_abr_loaded = false;
        } else
            ldac_abr_loaded = true;
        return true;
    }
    return false;
}


bool ldac_encoder_load() {
    if (!_ldac_encoder_load()) {
        pa_log_debug("Cannot load the LDAC encoder library");
        ldac_encoder_unload();
        return false;
    }
    return true;
}

bool is_ldac_abr_loaded() {
    return ldac_abr_lib_h ? true : false;
}
