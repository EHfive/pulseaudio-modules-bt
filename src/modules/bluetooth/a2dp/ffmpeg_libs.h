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

#ifndef PULSEAUDIO_MODULES_BT_FFMPEG_H
#define PULSEAUDIO_MODULES_BT_FFMPEG_H

#include <stdbool.h>
#include <libavcodec/avcodec.h>
#include <libavutil/samplefmt.h>

typedef AVCodec *(*avcodec_find_decoder_func_t)(enum AVCodecID id);

typedef AVCodec *(*avcodec_find_encoder_func_t)(enum AVCodecID id);

typedef AVPacket *(*av_packet_alloc_func_t)(void);

typedef void (*av_packet_free_func_t)(AVPacket **pkt);

typedef int (*avcodec_send_packet_func_t)(AVCodecContext *avctx, const AVPacket *avpkt);

typedef int (*avcodec_receive_frame_func_t)(AVCodecContext *avctx, AVFrame *frame);

typedef int (*avcodec_send_frame_func_t)(AVCodecContext *avctx, const AVFrame *frame);

typedef int (*avcodec_receive_packet_func_t)(AVCodecContext *avctx, AVPacket *avpkt);

typedef void (*avcodec_flush_buffers_func_t)(AVCodecContext *avctx);

typedef AVCodecContext *(*avcodec_alloc_context3_func_t)(const AVCodec *codec);

typedef void (*avcodec_free_context_func_t)(AVCodecContext **avctx);

typedef int (*avcodec_open2_func_t)(AVCodecContext *avctx, const AVCodec *codec, AVDictionary **options);


extern avcodec_find_decoder_func_t avcodec_find_decoder_func;
extern avcodec_find_encoder_func_t avcodec_find_encoder_func;
extern av_packet_alloc_func_t av_packet_alloc_func;
extern av_packet_free_func_t av_packet_free_func;
extern avcodec_send_packet_func_t avcodec_send_packet_func;
extern avcodec_receive_frame_func_t avcodec_receive_frame_func;
extern avcodec_send_frame_func_t avcodec_send_frame_func;
extern avcodec_receive_packet_func_t avcodec_receive_packet_func;
extern avcodec_flush_buffers_func_t avcodec_flush_buffers_func;
extern avcodec_alloc_context3_func_t avcodec_alloc_context3_func;
extern avcodec_free_context_func_t avcodec_free_context_func;
extern avcodec_open2_func_t avcodec_open2_func;


typedef AVFrame *(*av_frame_alloc_func_t)(void);


typedef int (*av_frame_get_buffer_func_t)(AVFrame *frame, int align);

typedef int (*av_frame_make_writable_func_t)(AVFrame *frame);

typedef void (*av_frame_free_func_t)(AVFrame **frame);


extern av_frame_alloc_func_t av_frame_alloc_func;
extern av_frame_get_buffer_func_t av_frame_get_buffer_func;
extern av_frame_make_writable_func_t av_frame_make_writable_func;
extern av_frame_free_func_t av_frame_free_func;


bool ffmpeg_libs_load();

#endif //PULSEAUDIO_MODULES_BT_FFMPEG_H
