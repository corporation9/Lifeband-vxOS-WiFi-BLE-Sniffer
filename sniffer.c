/*
    Copyright (C) Corporation 9 Limited - All Rights Reserved
    Unauthorized copying of this file, via any medium is strictly prohibited
    Proprietary and confidential
*/

#include "sniffer.h"

static const char * TAG = "sniffer";

// ----------------------------
// Promiscuous receiver callback
// This is called each time when a new packet is received
//
static void sniffer_esp_promis_rx_cb(void * buf,
    wifi_promiscuous_pkt_type_t type) {

    switch (type) {
        case WIFI_PKT_MGMT: {       // Management Frame is detected

            wifi_promiscuous_pkt_t * raw_pkt = (wifi_promiscuous_pkt_t *)buf;

            if (raw_pkt->rx_ctrl.sig_len >= sizeof(sniffer_80211_mac_header_t)) {   // Length of payload is described by rx_ctrl.sig_len
                
                sniffer_80211_mac_header_t * mac_header = 
                    (sniffer_80211_mac_header_t *)raw_pkt->payload;
                
                sniffer_scanres_t scanres = {
                    .type = SNIFFER_SCANRES_NONE,

                    .rssi = raw_pkt->rx_ctrl.rssi,
                    .channel = vfi_ctx.channel,
                    .payload_size = raw_pkt->rx_ctrl.sig_len,

                    .payload = NULL
                };

                if (mac_header->fc.subtype == 0b1000                                      // if the packet is a beacon
                    && raw_pkt->rx_ctrl.sig_len >= sizeof(sniffer_80211_pkt_beacon_t)) {  // and won't cause a segfault
                    sniffer_80211_pkt_beacon_t * beacon_pkt = 
                        (sniffer_80211_pkt_beacon_t * )raw_pkt->payload;

                    scanres.type = SNIFFER_SCANRES_AP;
                    scanres.payload = beacon_pkt;
                    
                } else if (mac_header->fc.subtype == 0b1000                              
                    && raw_pkt->rx_ctrl.sig_len >= sizeof(sniffer_tracerfi_pkt_t)) {

                    sniffer_tracerfi_pkt_t * tracerfi_pkt = 
                        (sniffer_tracerfi_pkt_t *)raw_pkt->payload;

                    if (tracerfi_pkt->dest_mac.magic == TRACERFI_MAGIC) { // if the scanned device is tracer device,
                        scanres.type = SNIFFER_SCANRES_TFI;
                        scanres.payload = tracerfi_pkt;                        
                    }
                }

                if (scanres.type) {
                    sniffer_user_callback(&scanres);
                }
            }
            break;
        }
        default: {      // Do nothing for other Frames
            break;
        }
    }
}

static void sniffer_esp_gap_cb(esp_gap_ble_cb_event_t event, 
    esp_ble_gap_cb_param_t * param) {

    switch (event) {
        case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT: {
            ESP_ERROR_CHECK(esp_ble_gap_start_scanning(0));
            break;
        }

        case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT: {
            ESP_LOGI(TAG, "ble scan started!");
            break;
        }

        case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT: {
            ESP_LOGI(TAG, "ble scan stopped!");
            break;
        }

        case ESP_GAP_BLE_SCAN_RESULT_EVT: {

            struct ble_scan_result_evt_param * esp_scanres = &param->scan_rst;

            if (esp_scanres->search_evt != ESP_GAP_SEARCH_INQ_RES_EVT) { break; }

            sniffer_ble_pkt_t * ble_pkt = malloc(sizeof(sniffer_ble_pkt_t));

            ble_pkt->mac = esp_scanres->bda;
            ble_pkt->is_mac_random = esp_scanres->ble_addr_type == BLE_ADDR_TYPE_RANDOM;
            ble_pkt->adv_payload_size = esp_scanres->adv_data_len;
            ble_pkt->adv_payload = esp_scanres->ble_adv;

            sniffer_scanres_t scanres = {
                .type = SNIFFER_SCANRES_BLE,

                .rssi = esp_scanres->rssi,
                .channel = 0,
                .payload_size = (uint8_t)sizeof(*ble_pkt),
                .payload = (void *)ble_pkt
            };

            sniffer_user_callback(&scanres);

            free(ble_pkt);

            break;
        }

        default: {
            ESP_LOGI(TAG, "unhandled BLE event!");
            break;
        }
    }

}

// --------------------------
// Does a WIFI channel sweep/scan for all channels
// requires: ble + vfi driver begin, vfi sta begin
void sniffer_esp_scan(sniffer_scan_settings_t * set) {

    vfi_promis_begin(&sniffer_esp_promis_rx_cb);

    vfi_driver_set_channel(set->tfi_channel);
    vfi_driver_set_tx_power(set->tfi_power);

    sniffer_tracerfi_pkt_t tfi_tx_pkt = TRACERFI_DEFAULT_PACKET();
    ESP_ERROR_CHECK( esp_efuse_mac_get_default(tfi_tx_pkt.send_mac) );
    ESP_LOGI(TAG, "tx mac: " SNIFFER_FMT_MAC_STR, 
        SNIFFER_FMT_MAC_DECOMP(tfi_tx_pkt.send_mac));
    
    ESP_LOGI(TAG, "starting tracerfi txrx...");

    for (uint8_t n = 0; n < set->tfi_transmits; n++) {
        vfi_sta_tx(&tfi_tx_pkt, sizeof(tfi_tx_pkt));
        vTaskDelay(set->tfi_period / portTICK_PERIOD_MS);
    }

    ESP_LOGI(TAG, "starting ap scan...");

    for (uint8_t ch = 0; ch < 16; ch++) {                                   // Scan all available WIFI channels
        if ((set->mask.value & (1 << ch)) == 0) continue;     // if the channel bit isn't set in the mask, skip it
        vfi_driver_set_channel(ch + 1);                                     // Set the new WIFI channel
        ESP_LOGD(TAG, "Switched to channel %u", vfi_ctx.channel);
        vTaskDelay(set->ap_period / portTICK_PERIOD_MS);
    }

    vfi_promis_end();

    ESP_LOGI(TAG, "starting ble scan...");

    ble_scan_begin(&sniffer_esp_gap_cb);

    vTaskDelay(set->ble_period / portTICK_PERIOD_MS);

    ble_scan_end();

    ESP_LOGI(TAG, "done!");

}
