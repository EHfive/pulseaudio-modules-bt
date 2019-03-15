/*
 *  pulseaudio-modules-bt
 *
 *  Copyright  2019  Huang-Huang Bao
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

#ifndef PULSEAUDIO_MODULES_BT_LDAC_LIBS_H
#define PULSEAUDIO_MODULES_BT_LDAC_LIBS_H

#include <stdbool.h>
#include <ldacBT.h>
#include <ldacBT_abr.h>

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

extern ldacBT_get_handle_func_t ldacBT_get_handle_func;
extern ldacBT_free_handle_func_t ldacBT_free_handle_func;
extern ldacBT_close_handle_func_t ldacBT_close_handle_func;
extern ldacBT_get_version_func_t ldacBT_get_version_func;
extern ldacBT_get_sampling_freq_func_t ldacBT_get_sampling_freq_func;
extern ldacBT_get_bitrate_func_t ldacBT_get_bitrate_func;
extern ldacBT_init_handle_encode_func_t ldacBT_init_handle_encode_func;
extern ldacBT_set_eqmid_func_t ldacBT_set_eqmid_func;
extern ldacBT_get_eqmid_func_t ldacBT_get_eqmid_func;
extern ldacBT_alter_eqmid_priority_func_t ldacBT_alter_eqmid_priority_func;
extern ldacBT_encode_func_t ldacBT_encode_func;
extern ldacBT_get_error_code_func_t ldacBT_get_error_code_func;


extern ldac_ABR_get_handle_func_t ldac_ABR_get_handle_func;
extern ldac_ABR_free_handle_func_t ldac_ABR_free_handle_func;
extern ldac_ABR_Init_func_t ldac_ABR_Init_func;
extern ldac_ABR_set_thresholds_func_t ldac_ABR_set_thresholds_func;
extern ldac_ABR_Proc_func_t ldac_ABR_Proc_func;

bool ldac_encoder_load();

bool is_ldac_abr_loaded();

#endif //PULSEAUDIO_MODULES_BT_LDAC_LIBS_H
