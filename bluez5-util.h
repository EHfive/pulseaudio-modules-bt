#ifndef foobluez5utilhfoo
#define foobluez5utilhfoo

/***
  This file is part of PulseAudio.

  Copyright 2008-2013 João Paulo Rechi Vita

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#include <pulsecore/core.h>

#define PA_BLUETOOTH_UUID_A2DP_SOURCE "0000110a-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_A2DP_SINK   "0000110b-0000-1000-8000-00805f9b34fb"

/* There are two HSP HS UUIDs. The first one (older?) is used both as the HSP
 * profile identifier and as the HS role identifier, while the second one is
 * only used to identify the role. As far as PulseAudio is concerned, the two
 * UUIDs mean exactly the same thing. */
#define PA_BLUETOOTH_UUID_HSP_HS      "00001108-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_HSP_HS_ALT  "00001131-0000-1000-8000-00805f9b34fb"

#define PA_BLUETOOTH_UUID_HSP_AG      "00001112-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_HFP_HF      "0000111e-0000-1000-8000-00805f9b34fb"
#define PA_BLUETOOTH_UUID_HFP_AG      "0000111f-0000-1000-8000-00805f9b34fb"

typedef struct pa_bluetooth_transport pa_bluetooth_transport;
typedef struct pa_bluetooth_device pa_bluetooth_device;
typedef struct pa_bluetooth_adapter pa_bluetooth_adapter;
typedef struct pa_bluetooth_discovery pa_bluetooth_discovery;
typedef struct pa_bluetooth_backend pa_bluetooth_backend;

typedef enum pa_bluetooth_hook {
    PA_BLUETOOTH_HOOK_DEVICE_CONNECTION_CHANGED,          /* Call data: pa_bluetooth_device */
    PA_BLUETOOTH_HOOK_TRANSPORT_STATE_CHANGED,            /* Call data: pa_bluetooth_transport */
    PA_BLUETOOTH_HOOK_TRANSPORT_MICROPHONE_GAIN_CHANGED,  /* Call data: pa_bluetooth_transport */
    PA_BLUETOOTH_HOOK_TRANSPORT_SPEAKER_GAIN_CHANGED,     /* Call data: pa_bluetooth_transport */
    PA_BLUETOOTH_HOOK_MAX
} pa_bluetooth_hook_t;

typedef enum profile {
    PA_BLUETOOTH_PROFILE_A2DP_SINK,
    PA_BLUETOOTH_PROFILE_A2DP_SOURCE,
    PA_BLUETOOTH_PROFILE_HEADSET_HEAD_UNIT,
    PA_BLUETOOTH_PROFILE_HEADSET_AUDIO_GATEWAY,
    PA_BLUETOOTH_PROFILE_OFF
} pa_bluetooth_profile_t;
#define PA_BLUETOOTH_PROFILE_COUNT PA_BLUETOOTH_PROFILE_OFF

typedef enum pa_bluetooth_transport_state {
    PA_BLUETOOTH_TRANSPORT_STATE_DISCONNECTED,
    PA_BLUETOOTH_TRANSPORT_STATE_IDLE,
    PA_BLUETOOTH_TRANSPORT_STATE_PLAYING
} pa_bluetooth_transport_state_t;

typedef int (*pa_bluetooth_transport_acquire_cb)(pa_bluetooth_transport *t, bool optional, size_t *imtu, size_t *omtu);
typedef void (*pa_bluetooth_transport_release_cb)(pa_bluetooth_transport *t);
typedef void (*pa_bluetooth_transport_destroy_cb)(pa_bluetooth_transport *t);
typedef void (*pa_bluetooth_transport_set_speaker_gain_cb)(pa_bluetooth_transport *t, uint16_t gain);
typedef void (*pa_bluetooth_transport_set_microphone_gain_cb)(pa_bluetooth_transport *t, uint16_t gain);

struct pa_bluetooth_transport {
    pa_bluetooth_device *device;

    char *owner;
    char *path;
    pa_bluetooth_profile_t profile;

    uint8_t codec;
    uint8_t *config;
    size_t config_size;

    uint16_t microphone_gain;
    uint16_t speaker_gain;

    pa_bluetooth_transport_state_t state;

    pa_bluetooth_transport_acquire_cb acquire;
    pa_bluetooth_transport_release_cb release;
    pa_bluetooth_transport_destroy_cb destroy;
    pa_bluetooth_transport_set_speaker_gain_cb set_speaker_gain;
    pa_bluetooth_transport_set_microphone_gain_cb set_microphone_gain;
    void *userdata;
};

struct pa_bluetooth_device {
    pa_bluetooth_discovery *discovery;
    pa_bluetooth_adapter *adapter;

    bool properties_received;
    bool tried_to_link_with_adapter;
    bool valid;
    bool autodetect_mtu;

    /* Device information */
    char *path;
    char *adapter_path;
    char *alias;
    char *address;
    uint32_t class_of_device;
    pa_hashmap *uuids; /* char* -> char* (hashmap-as-a-set) */

    pa_bluetooth_transport *transports[PA_BLUETOOTH_PROFILE_COUNT];

    pa_time_event *wait_for_profiles_timer;
};

struct pa_bluetooth_adapter {
    pa_bluetooth_discovery *discovery;
    char *path;
    char *address;

    bool valid;
};

#ifdef HAVE_BLUEZ_5_OFONO_HEADSET
pa_bluetooth_backend *pa_bluetooth_ofono_backend_new(pa_core *c, pa_bluetooth_discovery *y);
void pa_bluetooth_ofono_backend_free(pa_bluetooth_backend *b);
#else
static inline pa_bluetooth_backend *pa_bluetooth_ofono_backend_new(pa_core *c, pa_bluetooth_discovery *y) {
    return NULL;
}
static inline void pa_bluetooth_ofono_backend_free(pa_bluetooth_backend *b) {}
#endif

#ifdef HAVE_BLUEZ_5_NATIVE_HEADSET
pa_bluetooth_backend *pa_bluetooth_native_backend_new(pa_core *c, pa_bluetooth_discovery *y, bool enable_hs_role);
void pa_bluetooth_native_backend_free(pa_bluetooth_backend *b);
void pa_bluetooth_native_backend_enable_hs_role(pa_bluetooth_backend *b, bool enable_hs_role);
#else
static inline pa_bluetooth_backend *pa_bluetooth_native_backend_new(pa_core *c, pa_bluetooth_discovery *y, bool enable_hs_role) {
    return NULL;
}
static inline void pa_bluetooth_native_backend_free(pa_bluetooth_backend *b) {}
static inline void pa_bluetooth_native_backend_enable_hs_role(pa_bluetooth_backend *b, bool enable_hs_role) {}
#endif

pa_bluetooth_transport *pa_bluetooth_transport_new(pa_bluetooth_device *d, const char *owner, const char *path,
                                                   pa_bluetooth_profile_t p, const uint8_t *config, size_t size);

void pa_bluetooth_transport_set_state(pa_bluetooth_transport *t, pa_bluetooth_transport_state_t state);
void pa_bluetooth_transport_put(pa_bluetooth_transport *t);
void pa_bluetooth_transport_unlink(pa_bluetooth_transport *t);
void pa_bluetooth_transport_free(pa_bluetooth_transport *t);

bool pa_bluetooth_device_any_transport_connected(const pa_bluetooth_device *d);

pa_bluetooth_device* pa_bluetooth_discovery_get_device_by_path(pa_bluetooth_discovery *y, const char *path);
pa_bluetooth_device* pa_bluetooth_discovery_get_device_by_address(pa_bluetooth_discovery *y, const char *remote, const char *local);

pa_hook* pa_bluetooth_discovery_hook(pa_bluetooth_discovery *y, pa_bluetooth_hook_t hook);

const char *pa_bluetooth_profile_to_string(pa_bluetooth_profile_t profile);

static inline bool pa_bluetooth_uuid_is_hsp_hs(const char *uuid) {
    return pa_streq(uuid, PA_BLUETOOTH_UUID_HSP_HS) || pa_streq(uuid, PA_BLUETOOTH_UUID_HSP_HS_ALT);
}

#define HEADSET_BACKEND_OFONO 0
#define HEADSET_BACKEND_NATIVE 1
#define HEADSET_BACKEND_AUTO 2

pa_bluetooth_discovery* pa_bluetooth_discovery_get(pa_core *core, int headset_backend);
pa_bluetooth_discovery* pa_bluetooth_discovery_ref(pa_bluetooth_discovery *y);
void pa_bluetooth_discovery_unref(pa_bluetooth_discovery *y);
void pa_bluetooth_discovery_set_ofono_running(pa_bluetooth_discovery *y, bool is_running);
#endif
