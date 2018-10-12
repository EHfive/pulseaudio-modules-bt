/*
 * Copyright (C) 2014 - 2017 Sony Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LDACBT_ABR_H_
#define _LDACBT_ABR_H_

/* This file contains the definitions, declarations and macros for an implementation of
 * LDAC Adaptive Bit Rate (hereinafter ABR) processing.
 *
 * The basic flow of the ABR processing is as follows:
 * - The program creates a handle of LDAC ABR API using ldac_ABR_get_handle().
 * - The program initializes the handle by setting the ldac_ABR_Proc() call interval to
 *   ldac_ABR_Init().
 *       The interval shall be as short as possible at the timing without accumulation
 *       of packet in the buffer if propagation environment is fine.
 * - The program reinitializes the handle by calling ldac_ABR_Init() again when the
 *   state of the TX queue changes greatly, such as clearing the queue.
 * - If the program demands to control the thresholds, then ldac_ABR_set_thresholds()
 *   should be called.
 * - The program sets flagEnable to "1" when allowing LDAC encode bitrate to be
 *   adjusted by ABR, and sets it to "0" if it is not allowed.
 * - The program calls ldac_ABR_Proc() at the interval set to ldac_ABR_Init() even if
 *   flagEnable is "0".
 *       The program passes TxQueueDepth and flagEnable to ldac_ABR_Proc() at this call,
 *       LDAC encode bitrate is adjusted only when flagEnable is "1".
 *       Otherwise, the internal parameters are updated and analyzed then returned.
 *       The ABR handle adjusts eqmid based on TxQueueDepth which is passed from the program.
 *       The ABR handle calls LDAC encode API ldacBT_alter_eqmid_priority() to adjust eqmid.
 *       The ABR handle calls LDAC encode API ldacBT_get_eqmid() to get current eqmid.
 * - The handle may be released with ldac_ABR_free_handle().
 *
 * Notes on debugging LDAC ABR:
 * The meaning of "works fine" is that the bit rate will be low in case of bad radio situation
 * and high in case of good radio situation.
 *
 * The bit rate transition can be debug by checking logcat messages from LDAC ABR library which
 * built with the following changes in Android.bp:
 *  - Adding "liblog" to shared_libs.
 *  - Adding "-DLOCAL_DEBUG" to cflags.
 * The messages are formated as follows:
 *       [LDAC ABR] - abrQualityModeID : 0 -- eqmid : 0 -- TxQue : 0
 *     where abrQualityModeID and eqmid related to the current bit rate and TxQue shows the depth
 *     of current Tx queue.
 *     The relationship between abrQualityModeID, eqmid and the bit rate is described in
 *     "ldacBT_abr.c".
 *
 * The bit rate transition can be estimated/debug by listening to the audio played on the SNK
 * device. This method cannot use to confirm the details of the bit rate transition, but useful
 * to know how LDAC ABR algorithm works in a field test without checking the log.
 * To try this method, rebuilding of the "libldacBT_enc" library with the following change in
 * Android.bp is required:
 *  - Adding "-DUSE_LDAC_ENC_SETTING_FOR_ABR_DEBUG" to cflags.
 * By defining the above macro, the lower the bit rate, the greatly lower the bandwidth of the audio
 * played on the SNK device. Therefore, the audio played on the SNK device will sounds like a
 * low-pass filtered sound when the bit rate is low and will sounds as usual when the bit rate is
 * enough high. It is recommend using sound such as white noise to hear those changes for the first
 * time.
 *
 * IMPORTANT:
 * These libraries modified as described above shall be used only to confirm the bit rate transition
 * and SHALL NOT BE USED FOR FINAL PRODUCTS.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LDAC_ABR_API
#define LDAC_ABR_API
#endif /* LDAC_ABR_API */

#include <ldacBT.h> /* HANDLE_LDAC_BT */

/* LDAC ABR handle type*/
typedef struct _ldacbt_abr_param * HANDLE_LDAC_ABR;

/* Allocation of LDAC ABR handle.
 *  Format
 *      HANDLE_LDAC_ABR  ldacBT_get_handle( void );
 *  Arguments
 *      None.
 *  Return value
 *      HANDLE_LDAC_ABR for success, NULL for failure.
 */
LDAC_ABR_API HANDLE_LDAC_ABR ldac_ABR_get_handle(void);

/* Release of LDAC ABR handle.
 *  Format
 *      void  ldac_ABR_free_handle( HANDLE_LDAC_ABR );
 *  Arguments
 *      hLdacAbr    HANDLE_LDAC_ABR    LDAC ABR handle.
 *  Return value
 *      None.
 */
LDAC_ABR_API void ldac_ABR_free_handle(HANDLE_LDAC_ABR hLdacAbr);

/* Initialize LDAC ABR.
 *  Format
 *      int  ldac_ABR_Init( HANDLE_LDAC_ABR, unsigned int );
 *  Arguments
 *      hLdacAbr        HANDLE_LDAC_ABR    LDAC ABR handle.
 *      interval_ms     unsigned int       interval in ms for calling ldac_ABR_Proc().
 *                                         interval of 1ms to 500ms is valid.
 *  Return value
 *      int: 0 for success, -1 for failure.
 */
LDAC_ABR_API int ldac_ABR_Init(HANDLE_LDAC_ABR hLdacAbr, unsigned int interval_ms);

/* Setup thresholds for LDAC ABR.
 *  Format
 *      int ldac_ABR_set_thresholds( HANDLE_LDAC_ABR, unsigned int, unsigned int, unsigned int );
 *  Arguments
 *      hLdacAbr            HANDLE_LDAC_ABR  LDAC ABR handle.
 *      thCritical          unsigned int     threshold for critical TxQueueDepth status.
 *      thDangerousTrend    unsigned int     threshold for dangerous trend of TxQueueDepth.
 *      thSafety4HQSQ       unsigned int     safety threshold for LDACBT_EQMID_HQ and
 *                                           LDACBT_EQMID_SQ.
 *  Return value
 *      int: 0 for success, -1 for failure.
 *  Remarks
 *    Those thresholds should be the number of packets stored in the TX queue and should be
 *    greater than 0.
 *    The thCritical and thDangerousTrend are used for all eqmid and thSafety4HQSQ is used
 *    only for LDACBT_EQMID_HQ and LDACBT_EQMID_SQ. Therefore, those thresholds must satisfy
 *    the following releationship:
 *        thCritical >= thDangerousTrend >= thSafety4HQSQ
 */
LDAC_ABR_API int ldac_ABR_set_thresholds(HANDLE_LDAC_ABR hLdacAbr, unsigned int thCritical,
                                    unsigned int thDangerousTrend, unsigned int thSafety4HQSQ);

/* LDAC ABR main process.
 *  Format
 *      int  ldac_ABR_Proc( HANDLE_LDAC_BT, HANDLE_LDAC_ABR, unsigned int, unsigned int );
 *  Arguments
 *      hLdacBt        HANDLE_LDAC_BT    LDAC handle.
 *      hLdacAbr       HANDLE_LDAC_ABR   LDAC ABR handle.
 *      TxQueueDepth   unsigned int      depth of TX queue.
 *      flagEnable     unsigned int      flag indicating whether ABR is allowed to adjust LDAC
 *                                       encode bitrate
 *  Return value
 *      int: updated Encode Quality Mode Index for success, -1 for failure.
 */
LDAC_ABR_API int ldac_ABR_Proc(HANDLE_LDAC_BT hLdacBt, HANDLE_LDAC_ABR hLdacAbr,
                                 unsigned int TxQueueDepth, unsigned int flagEnable);
#ifdef __cplusplus
}
#endif

#endif /* _LDACBT_ABR_H_ */

