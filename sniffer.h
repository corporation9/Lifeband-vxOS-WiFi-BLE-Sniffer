/*
    Copyright (C) Corporation 9 Limited - All Rights Reserved
    Unauthorized copying of this file, via any medium is strictly prohibited
    Proprietary and confidential
*/

#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#include <stdint.h>
#include <stddef.h>

#include "esp_wifi.h"
#include "esp_wifi_types.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"

#include "esp_event.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_log.h"

#include "nvs_flash.h"
#include "nvs.h"

#include "wifi.h"
#include "ble.h"
#include "viper_os.h"

// ----------------
// Sniffer settings

#define SNIFFER_CHANNEL_MASK_ALL    (sniffer_channel_mask_t){.value = 0b0011111111111111}  // Allowed wifi channels in other countries
#define SNIFFER_CHANNEL_MASK_US     (sniffer_channel_mask_t){.value = 0b0000011111111111} // Allowed wifi channels in USA
#define SNIFFER_CHANNEL_MASK_UK     (sniffer_channel_mask_t){.value = 0b0001111111111111} // Allowed wifi channels in UK/Sweden
#define SNIFFER_FMT_MAC_STR "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define SNIFFER_FMT_MAC_DECOMP(mac) (uint8_t)(mac)[0], (uint8_t)(mac)[1], (uint8_t)(mac)[2], (uint8_t)(mac)[3], (uint8_t)(mac)[4], (uint8_t)(mac)[5]

// -----------------
// Tracerfi settings

#define TRACERFI_VERSION (0)
#define TRACERFI_DEST_MAC ("TRACER")
#define TRACERFI_FOURCC ("TRFI")
#define TRACERFI_MAGIC (0x54524649)

#define TRACERFI_DEFAULT_PACKET() { \
    .fc = { \
        .vers = 0b00, \
        .type = 0b00, \
        .subtype = 0b1000, \
        .to_ds = 0b0, \
        .from_ds = 0b0, \
        .more_fragments = 0b0, \
        .retry = 0b0, \
        .power_mgmt = 0b1, \
        .more_data = 0b0, \
        .is_protected = 0b0, \
        .order = 0b0, \
    }, \
    .duration_id = 0, \
    .dest_mac = { \
        .magic = TRACERFI_MAGIC, \
        .version = TRACERFI_VERSION \
    }, \
};

// ------------------
// Struct definitions

typedef union { 
    struct {
        uint16_t ch1 : 1;
        uint16_t ch2 : 1;
        uint16_t ch3 : 1;
        uint16_t ch4 : 1;
        uint16_t ch5 : 1;
        uint16_t ch6 : 1;
        uint16_t ch7 : 1;
        uint16_t ch8 : 1;
        uint16_t ch9 : 1;
        uint16_t ch10 : 1;
        uint16_t ch11 : 1;
        uint16_t ch12 : 1;
        uint16_t ch13 : 1;
        uint16_t ch14 : 1;
    };
    uint16_t value;
} sniffer_channel_mask_t;

typedef enum {
    SNIFFER_SCANRES_NONE = 0,
    SNIFFER_SCANRES_TFI,
    SNIFFER_SCANRES_AP,
    SNIFFER_SCANRES_BLE,
    SNIFFER_SCANRES_BT,
    SNIFFER_SCANRES_MAX
} sniffer_scanres_type_t;

typedef struct {
    sniffer_scanres_type_t type;

    int8_t rssi;
    uint8_t channel;
    size_t payload_size;

    void * payload;
} sniffer_scanres_t;

typedef struct {
    sniffer_channel_mask_t mask;
    uint32_t ap_period;
    uint32_t ble_period;
    uint32_t tfi_period;
    uint8_t tfi_transmits;
    uint8_t tfi_channel;
    int8_t tfi_power;
} sniffer_scan_settings_t;

typedef struct {
    uint16_t vers : 2;
    uint16_t type : 2;
    uint16_t subtype : 4;
    uint16_t to_ds : 1;
    uint16_t from_ds : 1;
    uint16_t more_fragments : 1;
    uint16_t retry : 1;
    uint16_t power_mgmt : 1;
    uint16_t more_data : 1;
    uint16_t is_protected : 1;
    uint16_t order : 1;
} sniffer_80211_frame_control_t;

typedef struct {
    sniffer_80211_frame_control_t fc;
    uint16_t duration_id;

    uint8_t dest_mac[6];    // destination mac
    uint8_t send_mac[6];    // sender mac
    uint8_t bssid[6];       // bssid

    uint16_t seq_ctrl;      // sequence control
} sniffer_80211_mac_header_t;

typedef struct {
    sniffer_80211_mac_header_t head;
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capabilities;
    uint8_t ssid_elem_id;
    uint8_t ssid_len;
    char ssid_head;         // reference to get pointer to ssid
} sniffer_80211_pkt_beacon_t;

typedef struct {
    sniffer_80211_frame_control_t fc; // frame control header
    uint16_t duration_id;

    struct {
        uint32_t magic;     // tracer magic number. must be equal to TRACERFI_MAGIC
        uint8_t version;    // tracer protocol version.
        uint8_t reserved;   // reserved values, for future use
    } dest_mac;
    uint8_t send_mac[6];    // sender mac. must be device mac

    uint8_t reserved[6];    // reserved data. for now, is used to pad to at least 24 bytes.
} sniffer_tracerfi_pkt_t;

typedef struct {
    uint8_t * mac;
    uint8_t is_mac_random : 1;
    uint8_t adv_payload_size;
    uint8_t * adv_payload;
} sniffer_ble_pkt_t;

// -----------------------------
// Sniffer Function Declarations

void sniffer_user_callback(sniffer_scanres_t * info);   // called when sniffer recieves a packet
void sniffer_esp_scan(sniffer_scan_settings_t * ctx);   // Does a WIFI+BT channel sweep/scan for all channels

#endif
