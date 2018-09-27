/***
  This file is part of PulseAudio.

  Copyright 2006 Lennart Poettering
  Copyright 2009 Canonical Ltd
  Copyright (C) 2012 Intel Corporation

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/xmalloc.h>

#include <pulsecore/core.h>
#include <pulsecore/modargs.h>
#include <pulsecore/source-output.h>
#include <pulsecore/source.h>
#include <pulsecore/core-util.h>

PA_MODULE_AUTHOR("Frédéric Dalleau, Pali Rohár");
PA_MODULE_DESCRIPTION("Policy module to make using bluetooth devices out-of-the-box easier");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);
PA_MODULE_USAGE(
        "auto_switch=<Switch between hsp and a2dp profile? (0 - never, 1 - media.role=phone, 2 - heuristic> "
        "a2dp_source=<Handle a2dp_source card profile (sink role)?> "
        "ag=<Handle headset_audio_gateway card profile (headset role)?> ");

static const char* const valid_modargs[] = {
    "auto_switch",
    "a2dp_source",
    "ag",
    "hfgw",
    NULL
};

struct userdata {
    uint32_t auto_switch;
    bool enable_a2dp_source;
    bool enable_ag;
    pa_hook_slot *source_put_slot;
    pa_hook_slot *sink_put_slot;
    pa_hook_slot *source_output_put_slot;
    pa_hook_slot *source_output_unlink_slot;
    pa_hook_slot *card_init_profile_slot;
    pa_hook_slot *card_unlink_slot;
    pa_hook_slot *profile_available_changed_slot;
    pa_hashmap *will_need_revert_card_map;
};

/* When a source is created, loopback it to default sink */
static pa_hook_result_t source_put_hook_callback(pa_core *c, pa_source *source, void *userdata) {
    struct userdata *u = userdata;
    const char *s;
    const char *role;
    char *args;
    pa_module *m = NULL;

    pa_assert(c);
    pa_assert(source);

    /* Only consider bluetooth sinks and sources */
    s = pa_proplist_gets(source->proplist, PA_PROP_DEVICE_BUS);
    if (!s)
        return PA_HOOK_OK;

    if (!pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    s = pa_proplist_gets(source->proplist, "bluetooth.protocol");
    if (!s)
        return PA_HOOK_OK;

    if (u->enable_a2dp_source && pa_streq(s, "a2dp_source"))
        role = "music";
    else if (u->enable_ag && pa_streq(s, "headset_audio_gateway"))
        role = "phone";
    else {
        pa_log_debug("Profile %s cannot be selected for loopback", s);
        return PA_HOOK_OK;
    }

    /* Load module-loopback */
    args = pa_sprintf_malloc("source=\"%s\" source_dont_move=\"true\" sink_input_properties=\"media.role=%s\"", source->name,
                             role);
    (void) pa_module_load(&m, c, "module-loopback", args);
    pa_xfree(args);

    return PA_HOOK_OK;
}

/* When a sink is created, loopback it to default source */
static pa_hook_result_t sink_put_hook_callback(pa_core *c, pa_sink *sink, void *userdata) {
    struct userdata *u = userdata;
    const char *s;
    const char *role;
    char *args;
    pa_module *m = NULL;

    pa_assert(c);
    pa_assert(sink);

    /* Only consider bluetooth sinks and sources */
    s = pa_proplist_gets(sink->proplist, PA_PROP_DEVICE_BUS);
    if (!s)
        return PA_HOOK_OK;

    if (!pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    s = pa_proplist_gets(sink->proplist, "bluetooth.protocol");
    if (!s)
        return PA_HOOK_OK;

    if (u->enable_ag && pa_streq(s, "headset_audio_gateway"))
        role = "phone";
    else {
        pa_log_debug("Profile %s cannot be selected for loopback", s);
        return PA_HOOK_OK;
    }

    /* Load module-loopback */
    args = pa_sprintf_malloc("sink=\"%s\" sink_dont_move=\"true\" source_output_properties=\"media.role=%s\"", sink->name,
                             role);
    (void) pa_module_load(&m, c, "module-loopback", args);
    pa_xfree(args);

    return PA_HOOK_OK;
}

static void card_set_profile(struct userdata *u, pa_card *card, bool revert_to_a2dp)
{
    pa_card_profile *profile;
    void *state;

    /* Find available profile and activate it */
    PA_HASHMAP_FOREACH(profile, card->profiles, state) {
        if (profile->available == PA_AVAILABLE_NO)
            continue;

        /* Check for correct profile based on revert_to_a2dp */
        if (revert_to_a2dp) {
            if (!pa_streq(profile->name, "a2dp") && !pa_streq(profile->name, "a2dp_sink"))
                continue;
        } else {
            if (!pa_streq(profile->name, "hsp") && !pa_streq(profile->name, "headset_head_unit"))
                continue;
        }

        pa_log_debug("Setting card '%s' to profile '%s'", card->name, profile->name);

        if (pa_card_set_profile(card, profile, false) != 0) {
            pa_log_warn("Could not set profile '%s'", profile->name);
            continue;
        }

        /* When we are not in revert_to_a2dp phase flag this card for will_need_revert */
        if (!revert_to_a2dp)
            pa_hashmap_put(u->will_need_revert_card_map, card, PA_INT_TO_PTR(1));

        break;
    }
}

/* Switch profile for one card */
static void switch_profile(pa_card *card, bool revert_to_a2dp, void *userdata) {
    struct userdata *u = userdata;
    const char *s;

    /* Only consider bluetooth cards */
    s = pa_proplist_gets(card->proplist, PA_PROP_DEVICE_BUS);
    if (!s || !pa_streq(s, "bluetooth"))
        return;

    if (revert_to_a2dp) {
        /* In revert_to_a2dp phase only consider cards with will_need_revert flag and remove it */
        if (!pa_hashmap_remove(u->will_need_revert_card_map, card))
            return;

        /* Skip card if does not have active hsp profile */
        if (!pa_streq(card->active_profile->name, "hsp") && !pa_streq(card->active_profile->name, "headset_head_unit"))
            return;

        /* Skip card if already has active a2dp profile */
        if (pa_streq(card->active_profile->name, "a2dp") || pa_streq(card->active_profile->name, "a2dp_sink"))
            return;
    } else {
        /* Skip card if does not have active a2dp profile */
        if (!pa_streq(card->active_profile->name, "a2dp") && !pa_streq(card->active_profile->name, "a2dp_sink"))
            return;

        /* Skip card if already has active hsp profile */
        if (pa_streq(card->active_profile->name, "hsp") || pa_streq(card->active_profile->name, "headset_head_unit"))
            return;
    }

    card_set_profile(u, card, revert_to_a2dp);
}

/* Return true if we should ignore this source output */
static bool ignore_output(pa_source_output *source_output, void *userdata) {
    struct userdata *u = userdata;
    const char *s;

    /* New applications could set media.role for identifying streams */
    /* We are interested only in media.role=phone */
    s = pa_proplist_gets(source_output->proplist, PA_PROP_MEDIA_ROLE);
    if (s)
        return !pa_streq(s, "phone");

    /* If media.role is not set use some heuristic (if enabled) */
    if (u->auto_switch != 2)
        return true;

    /* Ignore if resample method is peaks (used by desktop volume programs) */
    if (pa_source_output_get_resample_method(source_output) == PA_RESAMPLER_PEAKS)
        return true;

    /* Ignore if there is no client/application assigned (used by virtual stream) */
    if (!source_output->client)
        return true;

    /* Ignore if recording from monitor of sink */
    if (source_output->direct_on_input)
        return true;

    return false;
}

static unsigned source_output_count(pa_core *c, void *userdata) {
    pa_source_output *source_output;
    uint32_t idx;
    unsigned count = 0;

    PA_IDXSET_FOREACH(source_output, c->source_outputs, idx)
        if (!ignore_output(source_output, userdata))
            ++count;

    return count;
}

/* Switch profile for all cards */
static void switch_profile_all(pa_idxset *cards, bool revert_to_a2dp, void *userdata) {
    pa_card *card;
    uint32_t idx;

    PA_IDXSET_FOREACH(card, cards, idx)
        switch_profile(card, revert_to_a2dp, userdata);
}

/* When a source output is created, switch profile a2dp to profile hsp */
static pa_hook_result_t source_output_put_hook_callback(pa_core *c, pa_source_output *source_output, void *userdata) {
    pa_assert(c);
    pa_assert(source_output);

    if (ignore_output(source_output, userdata))
        return PA_HOOK_OK;

    switch_profile_all(c->cards, false, userdata);
    return PA_HOOK_OK;
}

/* When all source outputs are unlinked, switch profile hsp back back to profile a2dp */
static pa_hook_result_t source_output_unlink_hook_callback(pa_core *c, pa_source_output *source_output, void *userdata) {
    pa_assert(c);
    pa_assert(source_output);

    if (ignore_output(source_output, userdata))
        return PA_HOOK_OK;

    /* If there are still some source outputs do nothing. */
    if (source_output_count(c, userdata) > 0)
        return PA_HOOK_OK;

    switch_profile_all(c->cards, true, userdata);
    return PA_HOOK_OK;
}

static pa_hook_result_t card_init_profile_hook_callback(pa_core *c, pa_card *card, void *userdata) {
    struct userdata *u = userdata;
    const char *s;

    pa_assert(c);
    pa_assert(card);

    if (source_output_count(c, userdata) == 0)
        return PA_HOOK_OK;

    /* Only consider bluetooth cards */
    s = pa_proplist_gets(card->proplist, PA_PROP_DEVICE_BUS);
    if (!s || !pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    /* Ignore card if has already set other initial profile than a2dp */
    if (card->active_profile &&
        !pa_streq(card->active_profile->name, "a2dp") &&
        !pa_streq(card->active_profile->name, "a2dp_sink"))
        return PA_HOOK_OK;

    /* Set initial profile to hsp */
    card_set_profile(u, card, false);

    /* Flag this card for will_need_revert */
    pa_hashmap_put(u->will_need_revert_card_map, card, PA_INT_TO_PTR(1));
    return PA_HOOK_OK;
}

static pa_hook_result_t card_unlink_hook_callback(pa_core *c, pa_card *card, void *userdata) {
    pa_assert(c);
    pa_assert(card);
    switch_profile(card, true, userdata);
    return PA_HOOK_OK;
}

static pa_card_profile *find_best_profile(pa_card *card) {
    void *state;
    pa_card_profile *profile;
    pa_card_profile *result = card->active_profile;

    PA_HASHMAP_FOREACH(profile, card->profiles, state) {
        if (profile->available == PA_AVAILABLE_NO)
            continue;

        if (result == NULL ||
            (profile->available == PA_AVAILABLE_YES && result->available == PA_AVAILABLE_UNKNOWN) ||
            (profile->available == result->available && profile->priority > result->priority))
            result = profile;
    }

    return result;
}

static pa_hook_result_t profile_available_hook_callback(pa_core *c, pa_card_profile *profile, void *userdata) {
    pa_card *card;
    const char *s;
    bool is_active_profile;
    pa_card_profile *selected_profile;

    pa_assert(c);
    pa_assert(profile);
    pa_assert_se((card = profile->card));

    /* Only consider bluetooth cards */
    s = pa_proplist_gets(card->proplist, PA_PROP_DEVICE_BUS);
    if (!s || !pa_streq(s, "bluetooth"))
        return PA_HOOK_OK;

    /* Do not automatically switch profiles for headsets, just in case */
    if (pa_streq(profile->name, "a2dp_sink") || pa_streq(profile->name, "headset_head_unit"))
        return PA_HOOK_OK;

    is_active_profile = card->active_profile == profile;

    if (profile->available == PA_AVAILABLE_YES) {
        if (is_active_profile)
            return PA_HOOK_OK;

        if (card->active_profile->available == PA_AVAILABLE_YES && card->active_profile->priority >= profile->priority)
            return PA_HOOK_OK;

        selected_profile = profile;
    } else {
        if (!is_active_profile)
            return PA_HOOK_OK;

        pa_assert_se((selected_profile = find_best_profile(card)));

        if (selected_profile == card->active_profile)
            return PA_HOOK_OK;
    }

    pa_log_debug("Setting card '%s' to profile '%s'", card->name, selected_profile->name);

    if (pa_card_set_profile(card, selected_profile, false) != 0)
        pa_log_warn("Could not set profile '%s'", selected_profile->name);

    return PA_HOOK_OK;
}

static void handle_all_profiles(pa_core *core) {
    pa_card *card;
    uint32_t state;

    PA_IDXSET_FOREACH(card, core->cards, state) {
        pa_card_profile *profile;
        void *state2;

        PA_HASHMAP_FOREACH(profile, card->profiles, state2)
            profile_available_hook_callback(core, profile, NULL);
    }
}

int pa__init(pa_module *m) {
    pa_modargs *ma;
    struct userdata *u;

    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log_error("Failed to parse module arguments");
        goto fail;
    }

    m->userdata = u = pa_xnew0(struct userdata, 1);

    u->auto_switch = 1;

    if (pa_modargs_get_value(ma, "auto_switch", NULL)) {
        bool auto_switch_bool;

        /* auto_switch originally took a boolean value, let's keep
         * compatibility with configuration files that still pass a boolean. */
        if (pa_modargs_get_value_boolean(ma, "auto_switch", &auto_switch_bool) >= 0) {
            if (auto_switch_bool)
                u->auto_switch = 1;
            else
                u->auto_switch = 0;

        } else if (pa_modargs_get_value_u32(ma, "auto_switch", &u->auto_switch) < 0) {
            pa_log("Failed to parse auto_switch argument.");
            goto fail;
        }
    }

    u->enable_a2dp_source = true;
    if (pa_modargs_get_value_boolean(ma, "a2dp_source", &u->enable_a2dp_source) < 0) {
        pa_log("Failed to parse a2dp_source argument.");
        goto fail;
    }

    u->enable_ag = true;
    if (pa_modargs_get_value_boolean(ma, "ag", &u->enable_ag) < 0) {
        pa_log("Failed to parse ag argument.");
        goto fail;
    }

    u->will_need_revert_card_map = pa_hashmap_new(pa_idxset_trivial_hash_func, pa_idxset_trivial_compare_func);

    u->source_put_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SOURCE_PUT], PA_HOOK_NORMAL,
                                         (pa_hook_cb_t) source_put_hook_callback, u);

    u->sink_put_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SINK_PUT], PA_HOOK_NORMAL,
                                       (pa_hook_cb_t) sink_put_hook_callback, u);

    if (u->auto_switch) {
        u->source_output_put_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SOURCE_OUTPUT_PUT], PA_HOOK_NORMAL,
                                                    (pa_hook_cb_t) source_output_put_hook_callback, u);

        u->source_output_unlink_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_SOURCE_OUTPUT_UNLINK_POST], PA_HOOK_NORMAL,
                                                       (pa_hook_cb_t) source_output_unlink_hook_callback, u);

        u->card_init_profile_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_CARD_CHOOSE_INITIAL_PROFILE], PA_HOOK_NORMAL,
                                           (pa_hook_cb_t) card_init_profile_hook_callback, u);

        u->card_unlink_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_CARD_UNLINK], PA_HOOK_NORMAL,
                                           (pa_hook_cb_t) card_unlink_hook_callback, u);
    }

    u->profile_available_changed_slot = pa_hook_connect(&m->core->hooks[PA_CORE_HOOK_CARD_PROFILE_AVAILABLE_CHANGED],
                                                        PA_HOOK_NORMAL, (pa_hook_cb_t) profile_available_hook_callback, u);

    handle_all_profiles(m->core);

    pa_modargs_free(ma);
    return 0;

fail:
    if (ma)
        pa_modargs_free(ma);
    return -1;
}

void pa__done(pa_module *m) {
    struct userdata *u;

    pa_assert(m);

    if (!(u = m->userdata))
        return;

    if (u->source_put_slot)
        pa_hook_slot_free(u->source_put_slot);

    if (u->sink_put_slot)
        pa_hook_slot_free(u->sink_put_slot);

    if (u->source_output_put_slot)
        pa_hook_slot_free(u->source_output_put_slot);

    if (u->source_output_unlink_slot)
        pa_hook_slot_free(u->source_output_unlink_slot);

    if (u->card_init_profile_slot)
        pa_hook_slot_free(u->card_init_profile_slot);

    if (u->card_unlink_slot)
        pa_hook_slot_free(u->card_unlink_slot);

    if (u->profile_available_changed_slot)
        pa_hook_slot_free(u->profile_available_changed_slot);

    pa_hashmap_free(u->will_need_revert_card_map);

    pa_xfree(u);
}
