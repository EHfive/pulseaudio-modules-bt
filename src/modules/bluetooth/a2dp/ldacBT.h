/*
 * Copyright (C) 2013 - 2016 Sony Corporation
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

#ifndef _LDACBT_H_
#define _LDACBT_H_
#ifdef __cplusplus
extern "C" {
#endif
#ifndef LDACBT_API
#define LDACBT_API
#endif /* LDACBT_API  */

/* This file contains the definitions, declarations and macros for an implimentation of 
 * LDAC encode processing.
 *
 * The basic flow of the encode processing is as follows:
 * - The program creates an handle of an LDAC api using ldacBT_get_handle().
 * - The program initialize the handle for encode using ldacBT_init_handle_encode().
 * - The program calls ldacBT_encode() to encode data.
 * - If the program demands to control the Encode Quality Mode Index, then one of the following
 *   should be called:
 *     - ldacBT_set_eqmid()
 *     - ldacBT_alter_eqmid()
 * - The program finishes the encoding with passing NULL to input pcm buffer for ldacBT_encode(),
 *   which enables the encoder to encode remaining data in its input buffers.
 * - The handle may be closed using ldacBT_close_handle() then used again, or released with
 *   ldacBT_free_handle().
 * - The rest of the set functions should be called only if it is needed by the client.
 *
 *
 * Note for an implimentation
 * - Error processing
 *     When continuous processing for next frame is performed after error detection, following
 *     processing must be carried out using C function provided in the library.
 *      - Release of internal variables in encode processing using ldacBT_close_handle().
 *      - Allocation and initialization of internal variables in encode processing using
 *        ldacBT_init_handle_encode().
 *     Note that the encoded output for a few frames will not be present just after error recovery.
 *
 * - Resuming of the encode processing from an interruption
 *     In case of resuming of the encode processing from interruption (such as changing
 *     configuration, seeking and playback), initialization of internal variables in encode
 *     processing must be carried out as error processing described above.
 *     Note that the encoded output for a few frames will not be present just after initialization
 *     as above.
 *
 *
 * Glossary
 *  channel_config_index (cci)
 *    The channel setting information for ldaclib.
 *    See ldacBT_cm_to_cci() to get value from channel_mode.
 *
 *  channel_mode (cm)
 *    The channel setting information for LDAC specification of Bluetooth A2DP.
 *    See ldacBT_cci_to_cm() to get value from channel_config_index.
 *
 *  ldac_transport_frame
 *    See LDAC specification of bluetooth A2DP.
 *
 *  Maximum Transmission Unit (MTU)
 *    The minimum MTU that a L2CAP implementation for LDAC shall support is 679 bytes, because LDAC
 *    is optimized with 2-DH5 packet as its target.
 *
 *  frame
 *    An audio signal sequence representing a certain number of PCM audio signals.
 *    Encoding and decoding are processed frame by frame in LDAC. Number of samples in a frame is
 *    determined by sampling frequency as described below.
 *
 *  Sampling frequency and frame sample.
 *    Supported sampling frequencies are 44.1, 48, 88.2 and 96 kHz.
 *    The relationship between sampling frequency and frame sample in LDAC are shown below.
 *       --------------------------------------------------------
 *      | sampling frequency       [kHz] | 44.1 | 48 | 88.2 | 96 |
 *      | frame sample [samples/channel] |     128   |     256   |
 *       --------------------------------------------------------
 *    Though the frame size varies in LDAC core as described in the table, the number of samples in
 *    input PCM signal for encoding is fixed to 128 sample/channel, and it is not affected by
 *    sampling frequency.
 */
#define LDACBT_ENC_LSU 128
#define LDACBT_MAX_LSU 512

/* channel_config_index.
 * Supported value are below.
 */
#define LDAC_CCI_MONO         0 /* MONO */
#define LDAC_CCI_DUAL_CHANNEL 1 /* DUAL CHANNEL */
#define LDAC_CCI_STEREO       2 /* STEREO */

/* PCM format.
 * Supported PCM format are shown below.
 *   - LDACBT_SMPL_FMT_S16 : signed 16bits little endian.
 *   - LDACBT_SMPL_FMT_S24 : signed 24bits little endian.
 *   - LDACBT_SMPL_FMT_S32 : signed 32bits little endian.
 *   - LDACBT_SMPL_FMT_F32 : single-precision floating point.
 * The data sequency must be interleaved format by 1 sample.
 * Ex) 2 channel audio, the data sequences are aligned as below.
 *       seq : |L[0]|R[0]|L[1]|R[1]|...
 */
typedef enum {
    LDACBT_SMPL_FMT_S16 = 0x2,
    LDACBT_SMPL_FMT_S24 = 0x3,
    LDACBT_SMPL_FMT_S32 = 0x4,
    LDACBT_SMPL_FMT_F32 = 0x5,
} LDACBT_SMPL_FMT_T;

/* Encode Quality Mode Index. (EQMID)
 *  The configuration of encoding in LDAC will be coordinated by "Encode Quality Mode Index"
 *  parameter. Configurable values are shown below.
 *   - LDACBT_EQMID_HQ : Encode setting for High Quality.
 *   - LDACBT_EQMID_SQ : Encode setting for Standard Quality.
 *   - LDACBT_EQMID_MQ : Encode setting for Mobile use Quality.
 *   - LDACBT_EQMID_ABR: Reserved EQMID for ABR. The value shall be 0x7F.
 */
enum {
    LDACBT_EQMID_HQ = 0,
    LDACBT_EQMID_SQ,
    LDACBT_EQMID_MQ,
    LDACBT_EQMID_NUM,     /* terminator */
    LDACBT_EQMID_ABR = 0x7F,
};

/* Bit rates
 *  Bit rates in each EQMID are depend on sampling frequency.
 *  In this API specification, these relations are shown below.
 *     ___________________________________________
 *    |                 | Sampling Frequency[kHz] |
 *    |      EQMID      | 44.1, 88.2 |   48, 96   |
 *    +-----------------+------------+------------+
 *    | LDACBT_EQMID_HQ |   909kbps  |   990kbps  |
 *    | LDACBT_EQMID_SQ |   606kbps  |   660kbps  |
 *    | LDACBT_EQMID_MQ |   303kbps  |   330kbps  |
 *     -------------------------------------------
 */

/* Maximum size of the "ldac_transport_frame" sequence at transportation. */
#define LDACBT_MAX_NBYTES 1024 /* byte */

/* Maximum number of channel for LDAC */
#define LDAC_PRCNCH 2

/* LDAC handle type */
typedef struct _st_ldacbt_handle * HANDLE_LDAC_BT;

/* Allocation of LDAC handle.
 *  Format
 *      HANDLE_LDAC_BT ldacBT_get_handle( void );
 *  Arguments
 *      None.
 *  Return value
 *      HANDLE_LDAC_BT for success, NULL for failure.
 */
LDACBT_API HANDLE_LDAC_BT ldacBT_get_handle( void );

/* Release of LDAC handle.
 *  Format
 *      void ldacBT_free_handle( HANDLE_LDAC_BT hLdacBt );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *  Return value
 *      None.
 */
LDACBT_API void ldacBT_free_handle( HANDLE_LDAC_BT hLdacBt );

/* Closing of initialized LDAC handle.
 * Closed handle can be initialized and used again.
 *  Format
 *      void ldacBT_close_handle( HANDLE_LDAC_BT hLdacBt );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *  Return value
 *      None.
 */
LDACBT_API void ldacBT_close_handle( HANDLE_LDAC_BT hLdacBt );

/* Acquisition of the library version.
 *  Format
 *      int  ldacBT_get_version( void );
 *  Arguments
 *      None.
 *  Return value
 *      int : version number.
 *              23-16 bit : major version
 *              15- 8 bit : minor version
 *               7- 0 bit : branch version
 *              Ex) 0x00010203 -> version 1.02.03
 */
LDACBT_API int  ldacBT_get_version( void );

/* Acquisition of the sampling frequency in current configuration.
 * The LDAC handle must be initialized by API function ldacBT_init_handle_encode() prior to
 * calling this function.
 *  Format
 *      int  ldacBT_get_sampling_freq( HANDLE_LDAC_BT hLdacBt );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *  Return value
 *      int : sampling frequency in current configuration. -1 for failure.
 */
LDACBT_API int  ldacBT_get_sampling_freq( HANDLE_LDAC_BT hLdacBt );

/* Acquisition of the Bit-rate.
 * The LDAC handle must be initialized by API function ldacBT_init_handle_encode() prior to
 * calling this function.
 *  Format
 *      int  ldacBT_get_bitrate( HANDLE_LDAC_BT hLdacBt );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *  Return value
 *      int : Bit-rate for previously processed ldac_transport_frame for success. -1 for failure.
 */
LDACBT_API int  ldacBT_get_bitrate( HANDLE_LDAC_BT hLdacBt );

/* Initialization of a LDAC handle for encode processing.
 * The LDAC handle must be allocated by API function ldacBT_get_handle() prior to calling this API.
 * "mtu" value should be configured to MTU size of AVDTP Transport Channel, which is determined by
 * SRC and SNK devices in Bluetooth transmission.
 * "eqmid" is configured to desired value of "Encode Quality Mode Index".
 * "cm" is configured to channel_mode in LDAC, which is determined by SRC and SNK devices in
 * Bluetooth transmission.
 * "fmt" is configured to input pcm audio format.
 * When the configuration of "mtu", "cm", or "sf" changed, the re-initialization is required. 
 *
 *  Format
 *      int  ldacBT_init_handle_encode( HANDLE_LDAC_BT hLdacBt, int mtu, int eqmid, int cm,
 *                                      LDACBT_SMPL_FMT_T fmt, int sf );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *      mtu        int               MTU value. Unit:Byte.
 *      eqmid      int               Encode Quality Mode Index.
 *      cm         int               Information of the channel_mode.
 *      fmt        LDACBT_SMPL_FMT_T Audio format type of input pcm.
 *      sf         int               Sampling frequency of input pcm.
 *  Return value
 *      int : 0 for success, -1 for failure.
 */
LDACBT_API int  ldacBT_init_handle_encode( HANDLE_LDAC_BT hLdacBt, int mtu, int eqmid, int cm,
                                           LDACBT_SMPL_FMT_T fmt, int sf );

/* Configuration of Encode Quality Mode Index.
 * The LDAC handle must be initialized by API function ldacBT_init_handle_encode() prior to
 * calling this function.
 * The API function can be called at any time, after the completion of initializing.
 *  Format
 *      int  ldacBT_set_eqmid( HANDLE_LDAC_BT hLdacBt, int eqmid );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *      eqmid      int               Encode Quality Mode Index.
 *  Return value
 *      int : 0 for success, -1 for failure.
 */
LDACBT_API int  ldacBT_set_eqmid( HANDLE_LDAC_BT hLdacBt, int eqmid );

/* Acquisition of prescribed Encode Quality Mode Index in current configuration.
 * The LDAC handle must be initialized by API function ldacBT_init_handle_encode() prior to
 * calling this function.
 *  Format
 *      int  ldacBT_get_eqmid( HANDLE_LDAC_BT hLdacBt );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *  Return value
 *      int : Encode Quality Mode Index for success, -1 for failure.
 */
LDACBT_API int  ldacBT_get_eqmid( HANDLE_LDAC_BT hLdacBt );

/* Changing of configuration for Encode Quality Mode Index by one step.
 * The LDAC handle must be initialized by API function ldacBT_init_handle_encode() prior to
 * calling this function.
 * Configuralbe values for "priority" are shown below.
 *   - LDACBT_EQMID_INC_QUALITY    : Adjustment for EQMID by one step for the direction of
 *                                   getting close to LDACBT_EQMID_HQ.
 *   - LDACBT_EQMID_INC_CONNECTION : Adjustment for EQMID by one step for the direction of
 *                                   getting away from LDACBT_EQMID_HQ.
 * For restoring prescribed value for "Encode Quality Mode Index", it must be configured again by
 * API function ldacBT_init_handle_encode() or ldacBT_set_qmode().
 * A transition to the state other than "Encode Quality Mode Index" mention before may be occurred
 * caused by an adjustment using this API function.
 * The API function can be called at any time, after the completion of initializing.
 *  Format
 *      int  ldacBT_alter_eqmid_priority( HANDLE_LDAC_BT hLdacBt, int priority );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *      priority   int               The direction of changing EQMID.
 *  Return value
 *      int : 0 for success, -1 for failure.
 */
#define LDACBT_EQMID_INC_QUALITY     1
#define LDACBT_EQMID_INC_CONNECTION -1
LDACBT_API int  ldacBT_alter_eqmid_priority( HANDLE_LDAC_BT hLdacBt, int priority );


/* LDAC encode processing.
 * The LDAC handle must be initialized by API function ldacBT_init_handle_encode() prior to calling
 * this API function.
 * <Regarding on a input PCM signal>
 *  Number of samples in input PCM signal for encoding is fixed to 128 samples per channel, and it
 *  is not affected by sampling frequency.
 *
 *  The region in input signal buffer without any PCM signal must be filled with zero, if the
 *  number of samples is less than 128 samples.
 *
 *  The format of PCM signal is determined by "fmt" configured by API function
 *  ldacBT_init_handle_encode().
 *
 *  Total size of referenced PCM signal (in byte) will be set in "pcm_used" on return. The value of
 *  "Number of input samples * Number of channels * sizeof(PCM word length)" will be set in normal.
 *
 *  Finalize processing of encode will be carried out with setting "p_pcm" as zero.
 *
 * <Regarding on output encoded data>
 *  An output data in "ldac_transport_frame" sequence will be set to "p_stream" after several frame
 *  processing. So the output is not necessarily present at each calling of this API function.
 *
 *  The presence of the output can be verified by checking whether the value of "stream_wrote",
 *  representing the number of written bytes for "p_stream", is positive or not.
 *
 *  In addition, encoded data size for output will be determined by the value of "mtu" configured
 *  by API function ldacBT_init_handle_encode().
 *
 *  The number of "ldac_transport_frame" corresponding to "ldac_transport_frame" sequence as output
 *  will be set to "frame_num".
 *
 *  Format
 *      int  ldacBT_encode( HANDLE_LDAC_BT hLdacBt, void *p_pcm, int *pcm_used,
 *                          unsigned char *p_stream, int *stream_sz, int *frame_num );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *      p_pcm      void *            Input PCM signal sequence
 *      pcm_used   int *             Data size of referenced PCM singnal. Unit:Byte.
 *      p_stream   unsigned char *   Output "ldac_transport_frame" sequence.
 *      stream_sz  int *             Size of output data. Unit:Byte.
 *      frame_num  int *             Number of output "ldac_transport_frame"
 *  Return value
 *      int : 0 for success, -1 for failure.
 */
LDACBT_API int  ldacBT_encode( HANDLE_LDAC_BT hLdacBt, void *p_pcm, int *pcm_used,
                               unsigned char *p_stream, int *stream_sz, int *frame_num );

/* Acquisition of previously established error code.
 * The LDAC handle must be allocated by API function ldacBT_get_handle() prior to calling this function.
 * The details of error code are described below at the end of this header file.
 * Tips for error code handling.
 * The macro function LDACBT_FATAL() is useful to determine whether the error code is Fatal or not.
 *      Ex.) if( LDACBT_FATAL(err) ) // Fatal Error occurred.
 *
 * The macro function LDACBT_ERROR() is useful to determine whether the error occurred or not.
 *      Ex.) if( LDACBT_ERROR(err) ) // Error occurred.
 *
 * The macro function LDACBT_HANDLE_ERR() is useful to get the handle level error code.
 *      Ex.) err_handle_lv = LDACBT_HANDLE_ERR(err);
 *
 * The macro function LDACBT_BLOCK_ERR() is useful to get the block level error code.
 *      Ex.) err_block_lv = LDACBT_BLOCK_ERR(err);
 *
 *  Format
 *      int  ldacBT_get_error_code( HANDLE_LDAC_BT hLdacBt );
 *  Arguments
 *      hLdacBt    HANDLE_LDAC_BT    LDAC handle.
 *  Return value
 *      int : Error code.
 */
LDACBT_API int  ldacBT_get_error_code( HANDLE_LDAC_BT hLdacBt );

/*******************************************************************************
    Error Code
*******************************************************************************/
#define LDACBT_ERR_NONE                     0

/*    Non Fatal Error ***********************************************************/
#define LDACBT_ERR_NON_FATAL                1

/*    Non Fatal Error (Block Level) *********************************************/
#define LDACBT_ERR_BIT_ALLOCATION           5

/*    Non Fatal Error (Handle Level) ********************************************/
#define LDACBT_ERR_NOT_IMPLEMENTED          128
#define LDACBT_ERR_NON_FATAL_ENCODE         132

/*    Fatal Error ***************************************************************/
#define LDACBT_ERR_FATAL                    256

/*    Fatal Error (Block Level) *************************************************/
#define LDACBT_ERR_SYNTAX_BAND              260
#define LDACBT_ERR_SYNTAX_GRAD_A            261
#define LDACBT_ERR_SYNTAX_GRAD_B            262
#define LDACBT_ERR_SYNTAX_GRAD_C            263
#define LDACBT_ERR_SYNTAX_GRAD_D            264
#define LDACBT_ERR_SYNTAX_GRAD_E            265
#define LDACBT_ERR_SYNTAX_IDSF              266
#define LDACBT_ERR_SYNTAX_SPEC              267

#define LDACBT_ERR_BIT_PACKING              280

#define LDACBT_ERR_ALLOC_MEMORY             300

/*    Fatal Error (Handle Level) ************************************************/
#define LDACBT_ERR_FATAL_HANDLE             512

#define LDACBT_ERR_ILL_SYNCWORD             516
#define LDACBT_ERR_ILL_SMPL_FORMAT          517
#define LDACBT_ERR_ILL_PARAM                518

#define LDACBT_ERR_ASSERT_SAMPLING_FREQ     530
#define LDACBT_ERR_ASSERT_SUP_SAMPLING_FREQ 531
#define LDACBT_ERR_CHECK_SAMPLING_FREQ      532
#define LDACBT_ERR_ASSERT_CHANNEL_CONFIG    533
#define LDACBT_ERR_CHECK_CHANNEL_CONFIG     534
#define LDACBT_ERR_ASSERT_FRAME_LENGTH      535
#define LDACBT_ERR_ASSERT_SUP_FRAME_LENGTH  536
#define LDACBT_ERR_ASSERT_FRAME_STATUS      537
#define LDACBT_ERR_ASSERT_NSHIFT            538
#define LDACBT_ERR_ASSERT_CHANNEL_MODE      539

#define LDACBT_ERR_ENC_INIT_ALLOC           550
#define LDACBT_ERR_ENC_ILL_GRADMODE         551
#define LDACBT_ERR_ENC_ILL_GRADPAR_A        552
#define LDACBT_ERR_ENC_ILL_GRADPAR_B        553
#define LDACBT_ERR_ENC_ILL_GRADPAR_C        554
#define LDACBT_ERR_ENC_ILL_GRADPAR_D        555
#define LDACBT_ERR_ENC_ILL_NBANDS           556
#define LDACBT_ERR_PACK_BLOCK_FAILED        557

#define LDACBT_ERR_DEC_INIT_ALLOC           570
#define LDACBT_ERR_INPUT_BUFFER_SIZE        571
#define LDACBT_ERR_UNPACK_BLOCK_FAILED      572
#define LDACBT_ERR_UNPACK_BLOCK_ALIGN       573
#define LDACBT_ERR_UNPACK_FRAME_ALIGN       574
#define LDACBT_ERR_FRAME_LENGTH_OVER        575
#define LDACBT_ERR_FRAME_ALIGN_OVER         576


/* LDAC API for Encode */
#define LDACBT_ERR_ALTER_EQMID_LIMITED      21
#define LDACBT_ERR_HANDLE_NOT_INIT          1000
#define LDACBT_ERR_ILL_EQMID                1024
#define LDACBT_ERR_ILL_SAMPLING_FREQ        1025
#define LDACBT_ERR_ILL_NUM_CHANNEL          1026
#define LDACBT_ERR_ILL_MTU_SIZE             1027
/* LDAC API for Decode */
#define LDACBT_ERR_DEC_CONFIG_UPDATED       40


/* Macro Functions for Error Code ********************************************/
#define LDACBT_API_ERR(err)    ((err >> 20) & 0x0FFF)
#define LDACBT_HANDLE_ERR(err) ((err >> 10) & 0x03FF)
#define LDACBT_BLOCK_ERR(err)  ( err & 0x03FF)
#define LDACBT_ERROR(err)      ((LDACBT_ERR_NON_FATAL) <= LDACBT_API_ERR(err) ? 1 : 0)
#define LDACBT_FATAL(err)      ((LDACBT_ERR_FATAL) <= LDACBT_API_ERR(err) ? 1 : 0)



/* Codec Specific Information Elements for LDAC
 * (based on "LDAC Specification of Bluetooth A2DP Rev.2.0.1")
 *                  |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  0  |
 *  service_caps[4] |   SONY ID                                     | Octet0
 *  service_caps[5] |   SONY ID                                     | Octet1
 *  service_caps[6] |   SONY ID                                     | Octet2
 *  service_caps[7] |   SONY ID                                     | Octet3
 *  service_caps[8] |   SONY Specific Codec ID                      | Octet4
 *  service_caps[9] |   SONY Specific Codec ID                      | Octet5
 *  service_caps[A] |   RFA     |   Sampling Frequency              | Octet6
 *  service_caps[B] |   RFA                       | Channel Mode ID | Octet7
 */
#define LDACBT_MEDIA_CODEC_SC_SZ         (10+2)

/* [Octet 0-3] Vendor ID for SONY */
#define LDACBT_VENDOR_ID0 0x2D
#define LDACBT_VENDOR_ID1 0x01
#define LDACBT_VENDOR_ID2 0x0
#define LDACBT_VENDOR_ID3 0x0

/* [Octet 4-5] Vendor Specific A2DP Codec ID for LDAC */
#define LDACBT_CODEC_ID0 0xAA
#define LDACBT_CODEC_ID1 0x00

/* [Octet 6]
 * [b7,b6] : RFA
 *       Reserved for future additions.
 *       Bits with this designation shall be set to zero.
 *       Receivers shall ignore these bits.
 * -----------------------------------------------------
 * [b5-b0] : Sampling frequency and its associated bit field in LDAC are shown below.
 *    |  5  |  4  |  3  |  2  |  1  |  0  |
 *    |  o  |     |     |     |     |     |  44100
 *    |     |  o  |     |     |     |     |  48000
 *    |     |     |  o  |     |     |     |  88200
 *    |     |     |     |  o  |     |     |  96000
 *    |     |     |     |     |  o  |     | 176400
 *    |     |     |     |     |     |  o  | 192000
 *
 */
/* Support for 44.1kHz sampling frequency */
#define LDACBT_SAMPLING_FREQ_044100        0x20
/* Support for 48kHz sampling frequency */
#define LDACBT_SAMPLING_FREQ_048000        0x10
/* Support for 88.2kHz sampling frequency */
#define LDACBT_SAMPLING_FREQ_088200        0x08
/* Support for 96kHz sampling frequency */
#define LDACBT_SAMPLING_FREQ_096000        0x04
/* Support for 176.4kHz sampling frequency */
#define LDACBT_SAMPLING_FREQ_176400        0x02
/* Support for 192kHz sampling frequency */
#define LDACBT_SAMPLING_FREQ_192000        0x01

/* [Octet 7]
 * [b7-b3] : RFA
 *       Reserved for future additions.
 *       Bits with this designation shall be set to zero.
 *       Receivers shall ignore these bits.
 * ------------------------------------------------------
 * [b2-b0] : Channel mode and its associated bit field in LDAC are shown below.
 *    |  2  |  1  |  0  |
 *    |  o  |     |     | MONO
 *    |     |  o  |     | DUAL CHANNEL
 *    |     |     |  o  | STEREO
 */
/* Support for MONO */
#define LDACBT_CHANNEL_MODE_MONO           0x04
/* Support for DUAL CHANNEL */
#define LDACBT_CHANNEL_MODE_DUAL_CHANNEL   0x02
/* Support for STEREO */
#define LDACBT_CHANNEL_MODE_STEREO         0x01

#ifdef __cplusplus
}
#endif
#endif /* _LDACBT_H_ */
