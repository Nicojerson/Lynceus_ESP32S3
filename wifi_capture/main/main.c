/* wifi_capture - ESP32-S3: sniffer WiFi 2.4 GHz que manda CADA frame crudo por el cable serie.
 *
 * Este firmware NO analiza nada. Escucha, y por cada frame que oye manda un registro binario
 * con toda su informacion (tipo, canal, potencia, velocidad, encabezado 802.11 completo, y en
 * las balizas tambien sus elementos: SSID, canal, seguridad...). El analisis se hace en la PC
 * con analizar_wifi.py, y el archivo crudo que guarda capturar_wifi.py se puede reanalizar
 * todas las veces que quieras.
 *
 * Fase 1: barrido de canales SIN conectarse a nada (solo escucha).
 * Fase 2 (opcional): se conecta a TU router y le hace ping, para medir con trafico propio.
 *
 * No se guarda contenido de los datos: de cada frame de datos o control solo se envian los
 * primeros bytes (el encabezado). Las MAC SI viajan completas.
 *
 * Salida: UART0 (puerto rotulado COM de la placa), SER_BAUD baudios.
 * Trama:  A5 5A | largo u16 | t_us u32 | payload | CRC16-CCITT   (igual que serial_sender.c)
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdbool.h>
 #include <stdint.h>
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "freertos/semphr.h"
 #include "freertos/stream_buffer.h"
 #include "driver/uart.h"
 #include "esp_log.h"
 #include "esp_timer.h"
 #include "esp_event.h"
 #include "esp_netif.h"
 #include "esp_wifi.h"
 #include "nvs_flash.h"
 #include "ping/ping_sock.h"
 #include "lwip/ip_addr.h"
 
 /* ===================== CONFIGURACION ===================== */
 #define DURACION_SEG         180   /* fase 1: barrido de canales */
 #define DWELL_MS             400   /* tiempo en cada canal */
 #define CANAL_MIN            1
 #define CANAL_MAX            13
 #define CAPTURAR_CONTROL     1     /* 1 = tambien frames de control (ACK, RTS, CTS...) | 0 = solo gestion y datos */
 
 /* Fase 2 (opcional): conectarse a TU router y pingearlo */
 #define PING_ACTIVO          1     /* 1 = hacer fase 2 | 0 = solo barrido */
 #define WIFI_SSID            "TP-LINK_Lynceus"
 #define WIFI_PASS            "BatuLindo"
 #define PING_HZ              50
 #define PING_DURACION_SEG    60
 #define CONEXION_TIMEOUT_SEG 20
 
 /* Cable serie */
 #define SER_BAUD             921600   /* tiene que coincidir con capturar_wifi.py (--baud) */
 #define SER_TX_PIN           43
 #define SER_RX_PIN           44
 #define SER_BUF_SZ           (24 * 1024)
 /* ========================================================= */
 
 /* Cuantos bytes de cada frame se mandan (el resto se descarta) */
 #define CAP_BALIZA   384   /* balizas / probe responses: encabezado + elementos (SSID, canal, seguridad) */
 #define CAP_MGMT     64    /* otros frames de gestion (probe request lleva el SSID buscado) */
 #define CAP_OTROS    32    /* datos y control: solo encabezado */
 #define BALIZA_COMPLETA_CADA_US  2000000   /* la baliza completa de cada red se manda 1 vez cada 2 s */
 
 /* tipos de registro */
 #define REG_FRAME   1
 #define REG_EVENTO  2
 #define EV_START    1
 #define EV_CANAL    2
 #define EV_FASE     3
 #define EV_P2       4
 #define EV_STATS    5
 #define EV_END      6
 
 static volatile int      s_fase = 1;             /* 1 = barrido, 2 = conectado con ping */
 static volatile uint8_t  s_canal = 0;
 static volatile bool     s_got_ip = false;
 static volatile bool     s_reconectar = false;
 static esp_ping_handle_t s_ping = NULL;
 
 static StreamBufferHandle_t s_sb;
 static SemaphoreHandle_t    s_mtx;
 static volatile uint32_t    s_cb_total, s_enviados, s_perdidos;
 
 /* ---------- CRC y envio por el cable ---------- */
 static uint16_t crc16_ccitt(uint16_t c, const uint8_t *d, size_t n)
 {
     while (n--) {
         c ^= (uint16_t)(*d++) << 8;
         for (int i = 0; i < 8; i++) c = (c & 0x8000) ? (c << 1) ^ 0x1021 : (c << 1);
     }
     return c;
 }
 
 static bool emitir(const uint8_t *p, size_t n, TickType_t espera)
 {
     if (xSemaphoreTake(s_mtx, espera) != pdTRUE) { s_perdidos++; return false; }
     size_t need = 8 + n + 2;
     if (xStreamBufferSpacesAvailable(s_sb) < need) {         /* todo o nada */
         s_perdidos++;
         xSemaphoreGive(s_mtx);
         return false;
     }
     uint8_t h[8] = {0xA5, 0x5A};
     uint16_t l = (uint16_t)n;
     uint32_t t = (uint32_t)esp_timer_get_time();             /* reloj del ESP32 en us */
     memcpy(&h[2], &l, 2);
     memcpy(&h[4], &t, 4);
     uint16_t crc = crc16_ccitt(0xFFFF, &h[2], 6);
     crc = crc16_ccitt(crc, p, n);
     xStreamBufferSend(s_sb, h, 8, 0);
     xStreamBufferSend(s_sb, p, n, 0);
     xStreamBufferSend(s_sb, &crc, 2, 0);
     s_enviados++;
     xSemaphoreGive(s_mtx);
     return true;
 }
 
 /* eventos importantes: reintenta si el buffer esta lleno */
 static void emitir_seguro(const uint8_t *p, size_t n)
 {
     for (int i = 0; i < 40; i++) {
         if (emitir(p, n, pdMS_TO_TICKS(50))) return;
         vTaskDelay(pdMS_TO_TICKS(50));
     }
 }
 
 static void writer_task(void *arg)
 {
     (void)arg;
     static uint8_t chunk[512];
     for (;;) {
         size_t n = xStreamBufferReceive(s_sb, chunk, sizeof(chunk), portMAX_DELAY);
         if (n) uart_write_bytes(UART_NUM_0, chunk, n);
     }
 }
 
 static void serie_iniciar(void)
 {
     uart_config_t cfg = {
         .baud_rate = SER_BAUD, .data_bits = UART_DATA_8_BITS,
         .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
         .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
     };
     ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0));
     ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &cfg));
     ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, SER_TX_PIN, SER_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
     s_sb  = xStreamBufferCreate(SER_BUF_SZ, 1);
     s_mtx = xSemaphoreCreateMutex();
     xTaskCreate(writer_task, "cap_tx", 3072, NULL, 5, NULL);
 }
 
 /* ---------- eventos ---------- */
 static void emitir_start(void)
 {
     uint8_t b[16 + 33];
     size_t sl = strlen(WIFI_SSID);
     if (sl > 32) sl = 32;
     uint16_t dur = DURACION_SEG, dw = DWELL_MS, pd = PING_DURACION_SEG;
     b[0] = REG_EVENTO; b[1] = EV_START; b[2] = 1;            /* version del formato */
     memcpy(&b[3], &dur, 2);
     memcpy(&b[5], &dw, 2);
     b[7] = CANAL_MIN; b[8] = CANAL_MAX; b[9] = PING_ACTIVO; b[10] = PING_HZ;
     memcpy(&b[11], &pd, 2);
     b[13] = CONEXION_TIMEOUT_SEG; b[14] = CAPTURAR_CONTROL; b[15] = (uint8_t)sl;
     memcpy(&b[16], WIFI_SSID, sl);
     emitir_seguro(b, 16 + sl);
 }
 
 static void evento1(uint8_t ev, uint8_t v)
 {
     uint8_t b[3] = {REG_EVENTO, ev, v};
     emitir_seguro(b, 3);
 }
 
 static void emitir_stats(bool seguro)
 {
     uint8_t b[16];
     uint32_t cb = s_cb_total, en = s_enviados, pe = s_perdidos;
     b[0] = REG_EVENTO; b[1] = EV_STATS;
     memcpy(&b[2], &cb, 4); memcpy(&b[6], &en, 4); memcpy(&b[10], &pe, 4);
     b[14] = (uint8_t)s_fase; b[15] = s_canal;
     if (seguro) emitir_seguro(b, 16); else emitir(b, 16, pdMS_TO_TICKS(10));
 }
 
 static void stats_task(void *arg)
 {
     (void)arg;
     for (int n = 1;; n++) {
         vTaskDelay(pdMS_TO_TICKS(1000));
         emitir_stats(false);
         if (n % 5 == 0) emitir_start();                      /* por si la PC se conecto tarde */
     }
 }
 
 /* ---------- callback del sniffer (liviano, sin prints) ---------- */
 static struct { uint8_t bssid[6]; uint8_t sub; int64_t t; } s_bt[128];
 
 static unsigned bt_idx(const uint8_t *b, uint8_t sub)
 {
     return (b[3] * 31u + b[4] * 17u + b[5] + sub * 7u) % 128u;
 }
 
 static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
 {
     s_cb_total++;
     const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
     const wifi_pkt_rx_ctrl_t *rc = &pkt->rx_ctrl;
     const uint8_t *f = pkt->payload;
     int sig_len = (int)rc->sig_len;
 
     int cap = CAP_OTROS;
     int bi = -1;
     int64_t ahora = esp_timer_get_time();
     if (type == WIFI_PKT_MISC) {
         cap = 0;                                             /* sin payload util: solo metadatos */
     } else if (type == WIFI_PKT_MGMT && sig_len >= 24) {
         uint8_t st = (f[0] >> 4) & 0x0F;
         if (st == 8 || st == 5) {                            /* baliza / probe response */
             const uint8_t *bssid = f + 16;
             unsigned h = bt_idx(bssid, st);
             if (memcmp(s_bt[h].bssid, bssid, 6) == 0 && s_bt[h].sub == st &&
                 (ahora - s_bt[h].t) < BALIZA_COMPLETA_CADA_US) {
                 cap = 36;                                    /* ya la tenemos completa: solo encabezado */
             } else {
                 cap = CAP_BALIZA;
                 bi = (int)h;
             }
         } else {
             cap = CAP_MGMT;
         }
     }
     int stored = sig_len < cap ? sig_len : cap;
     if (stored < 0) stored = 0;
 
     uint8_t rec[18 + CAP_BALIZA];
     uint8_t flags = (uint8_t)((rc->sig_mode & 3) | ((rc->cwb & 1) << 2) | ((rc->sgi & 1) << 3) |
                               ((rc->stbc & 3) << 4) | ((rc->secondary_channel & 3) << 6));
     uint32_t rxts = (uint32_t)rc->timestamp;
     uint16_t sl = (uint16_t)sig_len, st16 = (uint16_t)stored;
     rec[0] = REG_FRAME;
     rec[1] = (uint8_t)s_fase;
     rec[2] = (uint8_t)type;
     rec[3] = (uint8_t)rc->channel;
     rec[4] = (uint8_t)(int8_t)rc->rssi;
     rec[5] = (uint8_t)(int8_t)rc->noise_floor;
     rec[6] = (uint8_t)rc->rate;
     rec[7] = flags;
     rec[8] = (uint8_t)rc->mcs;
     rec[9] = 0;
     memcpy(&rec[10], &rxts, 4);
     memcpy(&rec[14], &sl, 2);
     memcpy(&rec[16], &st16, 2);
     if (stored) memcpy(&rec[18], f, (size_t)stored);
 
     if (emitir(rec, 18 + (size_t)stored, 0) && bi >= 0) {   /* marcar la baliza completa solo si salio */
         memcpy(s_bt[bi].bssid, f + 16, 6);
         s_bt[bi].sub = (f[0] >> 4) & 0x0F;
         s_bt[bi].t = ahora;
     }
 }
 
 /* ---------- fase 2: conectar a tu router y pingear ---------- */
 static void on_evento(void *arg, esp_event_base_t base, int32_t id, void *data)
 {
     (void)arg; (void)data;
     if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
         s_got_ip = false;
         if (s_reconectar) esp_wifi_connect();
     } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
         s_got_ip = true;
     }
 }
 
 static void ping_nop(esp_ping_handle_t h, void *a) { (void)h; (void)a; }
 
 static bool iniciar_ping(uint8_t *ip4, uint8_t *gw4)
 {
     esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
     esp_netif_ip_info_t ip;
     if (sta == NULL || esp_netif_get_ip_info(sta, &ip) != ESP_OK || ip.gw.addr == 0) return false;
 
     memcpy(ip4, &ip.ip.addr, 4);
     memcpy(gw4, &ip.gw.addr, 4);
 
     char gw[16];
     esp_ip4addr_ntoa(&ip.gw, gw, sizeof(gw));
     ip_addr_t target;
     memset(&target, 0, sizeof(target));
     ipaddr_aton(gw, &target);
 
     esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
     cfg.target_addr     = target;
     cfg.count           = ESP_PING_COUNT_INFINITE;
     cfg.interval_ms     = 1000 / PING_HZ;
     cfg.data_size       = 1;
     cfg.task_stack_size = 4096;
     esp_ping_callbacks_t cbs = {
         .cb_args = NULL, .on_ping_success = ping_nop,
         .on_ping_timeout = ping_nop, .on_ping_end = ping_nop,
     };
     if (esp_ping_new_session(&cfg, &cbs, &s_ping) != ESP_OK || s_ping == NULL) { s_ping = NULL; return false; }
     esp_ping_start(s_ping);
     return true;
 }
 
 static void emitir_p2(uint8_t estado, uint8_t canal, const uint8_t *bssid, const uint8_t *ip4, const uint8_t *gw4)
 {
     uint8_t b[18];
     b[0] = REG_EVENTO; b[1] = EV_P2; b[2] = estado; b[3] = canal;
     memcpy(&b[4], bssid, 6); memcpy(&b[10], ip4, 4); memcpy(&b[14], gw4, 4);
     emitir_seguro(b, 18);
 }
 
 static wifi_promiscuous_filter_t filtro(void)
 {
     wifi_promiscuous_filter_t f = {
         .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
 #if CAPTURAR_CONTROL
                        | WIFI_PROMIS_FILTER_MASK_CTRL
 #endif
     };
     return f;
 }
 
 static void fase2_ejecutar(void)
 {
     static const uint8_t cero6[6] = {0}, cero4[4] = {0};
     s_reconectar = true;
     s_got_ip = false;
 
     wifi_config_t wc;
     memset(&wc, 0, sizeof(wc));
     strncpy((char *)wc.sta.ssid, WIFI_SSID, sizeof(wc.sta.ssid) - 1);
     strncpy((char *)wc.sta.password, WIFI_PASS, sizeof(wc.sta.password) - 1);
     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
     ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
     esp_wifi_connect();
 
     for (int i = 0; i < CONEXION_TIMEOUT_SEG * 10 && !s_got_ip; i++) vTaskDelay(pdMS_TO_TICKS(100));
     if (!s_got_ip) {                                         /* no conecto: la captura sigue siendo valida */
         s_reconectar = false;
         esp_wifi_disconnect();
         emitir_p2(2, 0, cero6, cero4, cero4);
         return;
     }
 
     uint8_t bssid[6] = {0}, canal = 0, ip4[4] = {0}, gw4[4] = {0};
     wifi_ap_record_t ap;
     if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) { memcpy(bssid, ap.bssid, 6); canal = ap.primary; }
     esp_wifi_set_ps(WIFI_PS_NONE);
 
     if (!iniciar_ping(ip4, gw4)) {
         s_reconectar = false;
         esp_wifi_disconnect();
         emitir_p2(3, canal, bssid, ip4, gw4);
         return;
     }
     emitir_p2(1, canal, bssid, ip4, gw4);                    /* antes de las muestras: asi se conoce el BSSID */
 
     s_canal = canal;
     wifi_promiscuous_filter_t filt = filtro();
     esp_wifi_set_promiscuous_filter(&filt);
     esp_wifi_set_promiscuous_rx_cb(sniffer_cb);
     s_fase = 2;
     evento1(EV_FASE, 2);
     esp_wifi_set_promiscuous(true);
     vTaskDelay(pdMS_TO_TICKS(PING_DURACION_SEG * 1000));
     s_fase = 1;
     evento1(EV_FASE, 1);
 
     esp_ping_stop(s_ping);
     esp_ping_delete_session(s_ping);
     s_ping = NULL;
     esp_wifi_set_promiscuous(false);
     s_reconectar = false;
     esp_wifi_disconnect();
 }
 
 /* ---------- principal ---------- */
 void app_main(void)
 {
     esp_log_level_set("*", ESP_LOG_NONE);                    /* silencio: por el cable solo viajan registros */
 
     esp_err_t e = nvs_flash_init();
     if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
         ESP_ERROR_CHECK(nvs_flash_erase());
         e = nvs_flash_init();
     }
     ESP_ERROR_CHECK(e);
     ESP_ERROR_CHECK(esp_netif_init());
     ESP_ERROR_CHECK(esp_event_loop_create_default());
     if (PING_ACTIVO) esp_netif_create_default_wifi_sta();
     ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_evento, NULL));
     ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_evento, NULL));
     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
     ESP_ERROR_CHECK(esp_wifi_init(&cfg));
     ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));      /* fase 1: sin conexion a ninguna red */
     ESP_ERROR_CHECK(esp_wifi_start());
 
     serie_iniciar();
     xTaskCreate(stats_task, "cap_stats", 3072, NULL, 4, NULL);
     emitir_start();
 
     wifi_promiscuous_filter_t filt = filtro();
     ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
     ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_cb));
     ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
 
     evento1(EV_FASE, 1);
     int64_t t0 = esp_timer_get_time();
     int ch = CANAL_MIN;
     while ((esp_timer_get_time() - t0) < (int64_t)DURACION_SEG * 1000000LL) {
         esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
         s_canal = (uint8_t)ch;
         evento1(EV_CANAL, (uint8_t)ch);
         vTaskDelay(pdMS_TO_TICKS(DWELL_MS));
         ch = (ch >= CANAL_MAX) ? CANAL_MIN : ch + 1;
     }
     esp_wifi_set_promiscuous(false);
     vTaskDelay(pdMS_TO_TICKS(200));
 
     if (PING_ACTIVO) fase2_ejecutar();                       /* conecta, pingea y mide */
 
     vTaskDelay(pdMS_TO_TICKS(1500));                         /* deja vaciar el buffer */
     emitir_stats(true);                                      /* contadores finales, justo antes del fin */
     evento1(EV_END, 0);
     while (1) vTaskDelay(pdMS_TO_TICKS(1000));               /* RESET para repetir */
 }