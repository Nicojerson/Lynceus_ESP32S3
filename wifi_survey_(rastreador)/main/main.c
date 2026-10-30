/* Encuesta pasiva de redes WiFi 2.4 GHz - ESP32-S3
 * Fase 1: barrido de canales SIN conectarse a nada (solo escucha).
 * Fase 2 (opcional): se conecta a TU router y le hace ping, para medir con trafico propio.
 * Solo se registran metadatos (MAC de routers, SSID, canal, potencia). No se guarda contenido. */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdbool.h>
 #include <stdint.h>
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "esp_log.h"
 #include "esp_timer.h"
 #include "esp_event.h"
 #include "esp_netif.h"
 #include "esp_wifi.h"
 #include "nvs_flash.h"
 #include "ping/ping_sock.h"
 #include "lwip/ip_addr.h"
 
 /* ===================== CONFIGURACION ===================== */
 #define MODO_BUSCAR          0     /* 0 = encuesta + informe | 1 = localizar una red (dBm cada 1 s) */
 #define DURACION_SEG         180   /* fase 1: barrido de canales */
 #define DWELL_MS             400
 #define CANAL_MIN            1
 #define CANAL_MAX            13
 
 /* Fase 2 (opcional): conectarse a TU router y pingearlo */
 #define PING_ACTIVO          1     /* 1 = hacer fase 2 | 0 = solo barrido */
 #define WIFI_SSID            "TP-LINK_Lynceus"
 #define WIFI_PASS            "BatuLindo"
 #define PING_HZ              50
 #define PING_DURACION_SEG    60
 #define CONEXION_TIMEOUT_SEG 20
 
 /* Tu red de referencia (OPCIONAL). Para no usar ninguna: MI_SSID "" y BSSID en ceros. */
 static const uint8_t MI_BSSID[6] = {0xf8, 0xd1, 0x11, 0x2d, 0xb9, 0x6e};
 #define MI_SSID              "TP-LINK_Lynceus"
 #define MI_CANAL             6

 /* Red a localizar en MODO_BUSCAR (CUALQUIERA: copia su BSSID del informe). */
 static const uint8_t OBJETIVO_BSSID[6] = {0xf8, 0xd1, 0x11, 0x2d, 0xb9, 0x6e};
 /* ========================================================= */
 
 #define MAX_REDES 64
 #define MAX_DISP  160
 
 typedef struct {
     uint8_t  bssid[6];
     char     ssid[33];
     bool     ssid_visto, oculta;
     uint8_t  canal;
     uint8_t  seg;                 /* 0 abierta,1 WEP,2 WPA,3 WPA2,4 WPA3,5 WPA2/3 */
     uint32_t frames, f_mgmt, f_data, beacons;
     int32_t  rssi_sum;
     uint32_t rssi_n;
     int8_t   rssi_max;
     uint16_t n_disp;
 } red_t;
 
 typedef struct {
     uint8_t  mac[6];
     int16_t  red;                 /* -1 = busca red sin estar asociado */
     uint32_t frames;
     int32_t  rssi_sum;
     uint32_t rssi_n;
 } disp_t;
 
 static red_t  s_red[MAX_REDES];  static int s_n_red;
 static disp_t s_disp[MAX_DISP];  static int s_n_disp;
 static uint32_t s_total_frames, s_frames_mgmt, s_frames_data;
 static uint32_t s_desc_redes, s_desc_disp;
 static uint32_t s_frames_canal[15];
 static uint32_t s_listen_ms[15];
 static volatile int32_t  s_loc_sum;
 static volatile uint32_t s_loc_n;
 
 /* ---- estado de la fase 2 ---- */
 static volatile int  s_fase = 1;                 /* 1 = barrido, 2 = conectado con ping */
 static volatile bool s_got_ip = false;
 static volatile bool s_reconectar = false;
 static esp_ping_handle_t s_ping = NULL;
 static volatile uint32_t s_p2_prop, s_p2_aj, s_p2_rssi_n;
 static volatile int32_t  s_p2_rssi_sum;
 static int     s_p2_estado = 0;                  /* 0 no hecha, 1 OK, 2 no conecto, 3 sin ping */
 static uint8_t s_p2_canal;
 static uint8_t s_p2_bssid[6];
 static char    s_p2_ip[16], s_p2_gw[16];
 
 /* ---------- utilidades ---------- */
 static char *mac_str(const uint8_t *m, char *out)
 {
     snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
     return out;
 }
 
 static const char *seg_txt(uint8_t s)
 {
     static const char *t[] = {"ABIERTA", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3"};
     return t[s > 5 ? 0 : s];
 }
 
 static const char *prox_txt(int rssi)
 {
     if (rssi >= -40) return "MUY CERCA (~1-2 m)";
     if (rssi >= -55) return "CERCA (pocos metros)";
     if (rssi >= -70) return "MEDIA (otra habitacion / 5-15 m)";
     if (rssi >= -80) return "LEJOS";
     return "MUY LEJOS (borde de deteccion)";
 }
 
 static bool bssid_cero(const uint8_t *b)
 {
     for (int i = 0; i < 6; i++) if (b[i]) return false;
     return true;
 }
 
 static bool es_propia(const red_t *r)
 {
     if (!bssid_cero(MI_BSSID) && memcmp(r->bssid, MI_BSSID, 6) == 0) return true;
     if (MI_SSID[0] && r->ssid_visto && !r->oculta && strcmp(r->ssid, MI_SSID) == 0) return true;
     return false;
 }
 
 static int avg_rssi(const red_t *r)
 {
     return r->rssi_n ? (int)(r->rssi_sum / (int32_t)r->rssi_n) : -127;
 }
 
 static int buscar_red(const uint8_t *bssid)
 {
     for (int i = 0; i < s_n_red; i++)
         if (memcmp(s_red[i].bssid, bssid, 6) == 0) return i;
     if (s_n_red >= MAX_REDES) { s_desc_redes++; return -1; }
     red_t *r = &s_red[s_n_red];
     memset(r, 0, sizeof(*r));
     memcpy(r->bssid, bssid, 6);
     r->rssi_max = -127;
     return s_n_red++;
 }
 
 static int buscar_disp(const uint8_t *mac, int red)
 {
     for (int i = 0; i < s_n_disp; i++) {
         if (memcmp(s_disp[i].mac, mac, 6) == 0) {
             if (s_disp[i].red < 0 && red >= 0) { s_disp[i].red = red; s_red[red].n_disp++; }
             return i;
         }
     }
     if (s_n_disp >= MAX_DISP) { s_desc_disp++; return -1; }
     disp_t *d = &s_disp[s_n_disp];
     memset(d, 0, sizeof(*d));
     memcpy(d->mac, mac, 6);
     d->red = red;
     if (red >= 0) s_red[red].n_disp++;
     return s_n_disp++;
 }
 
 /* ---------- analisis de balizas / probe responses ---------- */
 static void rsn_akm(const uint8_t *ie, int l, bool *sae, bool *otro)
 {
     if (l < 10) return;
     int off = 6;
     int pc = ie[off] | (ie[off + 1] << 8);
     off += 2 + 4 * pc;
     if (off + 2 > l) return;
     int ac = ie[off] | (ie[off + 1] << 8);
     off += 2;
     for (int i = 0; i < ac && off + 4 <= l; i++, off += 4) {
         bool es_sae = ie[off] == 0x00 && ie[off + 1] == 0x0F && ie[off + 2] == 0xAC &&
                       (ie[off + 3] == 8 || ie[off + 3] == 9);
         if (es_sae) *sae = true; else *otro = true;
     }
 }
 
 static void parsear_baliza(red_t *r, const uint8_t *f, int len, uint8_t canal_rx)
 {
     if (len < 36) return;
     bool privacy = (f[34] | (f[35] << 8)) & 0x0010;
     bool rsn = false, sae = false, otro = false, wpa = false;
     uint8_t canal_ds = 0;
     const uint8_t *p = f + 36, *end = f + len;
     while (p + 2 <= end) {
         uint8_t id = p[0], l = p[1];
         if (p + 2 + l > end) break;
         const uint8_t *d = p + 2;
         if (id == 0) {                                   /* SSID */
             bool vacio = true;
             for (int i = 0; i < l; i++) if (d[i]) { vacio = false; break; }
             if (vacio) {
                 if (!r->ssid[0]) r->oculta = true;
             } else {
                 int n = l > 32 ? 32 : l;
                 for (int i = 0; i < n; i++) r->ssid[i] = (d[i] >= 32 && d[i] < 127) ? d[i] : '?';
                 r->ssid[n] = 0;
                 r->oculta = false;                       /* nombre revelado */
             }
             r->ssid_visto = true;
         } else if (id == 3 && l == 1) {
             canal_ds = d[0];
         } else if (id == 48) {
             rsn = true; rsn_akm(d, l, &sae, &otro);
         } else if (id == 221 && l >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01) {
             wpa = true;
         }
         p += 2 + l;
     }
     r->canal = canal_ds ? canal_ds : (r->canal ? r->canal : canal_rx);
     if (rsn)          r->seg = (sae && otro) ? 5 : (sae ? 4 : 3);
     else if (wpa)     r->seg = 2;
     else if (privacy) r->seg = 1;
     else              r->seg = 0;
 }
 
 /* ---------- callback del sniffer (liviano, sin prints) ---------- */
 static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
 {
     if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
     const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
     const uint8_t *f = pkt->payload;
     int len = (int)pkt->rx_ctrl.sig_len;
     if (len > 4) len -= 4;
     if (len < 24) return;
 
     int rssi = pkt->rx_ctrl.rssi;
     uint8_t canal_rx = pkt->rx_ctrl.channel;
     uint8_t tipo = (f[0] >> 2) & 0x03, subtipo = (f[0] >> 4) & 0x0F;
     bool to_ds = (f[1] & 0x01) != 0, from_ds = (f[1] & 0x02) != 0;
     const uint8_t *a1 = f + 4, *a2 = f + 10, *a3 = f + 16;
 
     const uint8_t *bssid = NULL, *estacion = NULL;
     bool est_tx = false, sin_red = false;
 
     if (tipo == 0) {
         if (subtipo == 4) {                              /* probe request */
             sin_red = true; estacion = a2; est_tx = true;
         } else {
             bssid = a3;
             if (subtipo <= 3 || subtipo == 11) {
                 if (memcmp(a2, a3, 6) == 0) estacion = a1;
                 else { estacion = a2; est_tx = true; }
             }
         }
     } else if (tipo == 2) {
         if (to_ds && from_ds) return;
         if (!to_ds && !from_ds)  bssid = a3;
         else if (to_ds)        { bssid = a1; estacion = a2; est_tx = true; }
         else                   { bssid = a2; estacion = a1; }
     } else {
         return;
     }
     if (!sin_red && (bssid[0] & 1)) return;
 
     if (s_fase == 2) {                                   /* fase con ping: solo contadores propios */
         if (!sin_red) {
             if (memcmp(bssid, s_p2_bssid, 6) == 0) {
                 s_p2_prop++;
                 if (memcmp(a2, bssid, 6) == 0) { s_p2_rssi_sum += rssi; s_p2_rssi_n++; }
             } else {
                 s_p2_aj++;
             }
         }
         return;
     }
 
     s_total_frames++;
     if (tipo == 0) s_frames_mgmt++; else s_frames_data++;
     if (canal_rx >= 1 && canal_rx <= 14) s_frames_canal[canal_rx]++;
 
     if (sin_red) {
         if (!(estacion[0] & 1)) {
             int di = buscar_disp(estacion, -1);
             if (di >= 0) s_disp[di].frames++;
         }
         return;
     }
 
     int ri = buscar_red(bssid);
     if (ri < 0) return;
     red_t *r = &s_red[ri];
     if (r->canal == 0) r->canal = canal_rx;              /* provisorio; la baliza lo corrige */
     r->frames++;
     if (tipo == 0) r->f_mgmt++; else r->f_data++;
 
     if (memcmp(a2, bssid, 6) == 0) {                     /* transmite el propio router */
         r->rssi_sum += rssi; r->rssi_n++;
         if (rssi > r->rssi_max) r->rssi_max = (int8_t)rssi;
         if (memcmp(bssid, OBJETIVO_BSSID, 6) == 0) { s_loc_sum += rssi; s_loc_n++; }
         if (tipo == 0 && (subtipo == 8 || subtipo == 5)) {
             if (subtipo == 8) r->beacons++;
             parsear_baliza(r, f, len, canal_rx);
         }
     }
 
     if (estacion && !(estacion[0] & 1) && memcmp(estacion, bssid, 6) != 0) {
         int di = buscar_disp(estacion, ri);
         if (di >= 0) {
             s_disp[di].frames++;
             if (est_tx) { s_disp[di].rssi_sum += rssi; s_disp[di].rssi_n++; }
         }
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
 
 static bool iniciar_ping(void)
 {
     esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
     esp_netif_ip_info_t ip;
     if (sta == NULL || esp_netif_get_ip_info(sta, &ip) != ESP_OK || ip.gw.addr == 0) return false;
 
     esp_ip4addr_ntoa(&ip.ip, s_p2_ip, sizeof(s_p2_ip));
     esp_ip4addr_ntoa(&ip.gw, s_p2_gw, sizeof(s_p2_gw));
 
     ip_addr_t target;
     memset(&target, 0, sizeof(target));
     ipaddr_aton(s_p2_gw, &target);
 
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
 
 static void fase2_ejecutar(void)
 {
     s_p2_estado = 2;
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
     if (!s_got_ip) {                                     /* no conecto: el informe sale igual */
         s_reconectar = false;
         esp_wifi_disconnect();
         return;
     }
 
     wifi_ap_record_t ap;
     if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) { memcpy(s_p2_bssid, ap.bssid, 6); s_p2_canal = ap.primary; }
     esp_wifi_set_ps(WIFI_PS_NONE);
 
     wifi_promiscuous_filter_t filt = {
         .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
     };
     esp_wifi_set_promiscuous_filter(&filt);
     esp_wifi_set_promiscuous_rx_cb(sniffer_cb);
     esp_wifi_set_promiscuous(true);
 
     s_p2_estado = 3;
     if (!iniciar_ping()) {
         s_reconectar = false;
         esp_wifi_set_promiscuous(false);
         esp_wifi_disconnect();
         return;
     }
     s_p2_prop = 0; s_p2_aj = 0; s_p2_rssi_sum = 0; s_p2_rssi_n = 0;
     s_fase = 2;
     vTaskDelay(pdMS_TO_TICKS(PING_DURACION_SEG * 1000));
     s_fase = 1;
 
     esp_ping_stop(s_ping);
     esp_ping_delete_session(s_ping);
     s_ping = NULL;
     esp_wifi_set_promiscuous(false);
     s_reconectar = false;
     esp_wifi_disconnect();
     s_p2_estado = 1;
 }
 
 /* ---------- informe ---------- */
 static void imprimir_fase2(void)
 {
     char b1[18];
     printf("\n [5] PRUEBA CON TRAFICO PROPIO (ping a tu router)\n");
     if (!PING_ACTIVO) {
         printf("   Desactivada (PING_ACTIVO 0).\n");
         return;
     }
     if (s_p2_estado == 2) {
         printf("   NO SE PUDO CONECTAR a '%s' en %d s (apagada, fuera de alcance o clave incorrecta).\n",
                WIFI_SSID, CONEXION_TIMEOUT_SEG);
         printf("   El resto del informe es valido.\n");
         return;
     }
     if (s_p2_estado == 3) {
         printf("   Se conecto a '%s' pero no pudo iniciar el ping.\n", WIFI_SSID);
         return;
     }
     uint32_t tot = s_p2_prop + s_p2_aj;
     int pct = tot ? (int)(100UL * s_p2_aj / tot) : 0;
     const char *v = pct < 15 ? "LIMPIO" : (pct < 50 ? "MODERADO" : "CONTAMINADO");
     printf("   Conectado a %s (BSSID %s), canal %u\n", WIFI_SSID, mac_str(s_p2_bssid, b1), (unsigned)s_p2_canal);
     printf("   IP del sensor %s | ping a %s, %d Hz, durante %d s\n", s_p2_ip, s_p2_gw, PING_HZ, PING_DURACION_SEG);
     printf("   Frames de tu router ..... %lu (%lu por segundo)\n",
            (unsigned long)s_p2_prop, (unsigned long)(s_p2_prop / PING_DURACION_SEG));
     printf("   Frames de otras redes ... %lu (%lu por segundo)\n",
            (unsigned long)s_p2_aj, (unsigned long)(s_p2_aj / PING_DURACION_SEG));
     if (s_p2_rssi_n)
         printf("   Senal del router ........ %d dBm promedio\n", (int)(s_p2_rssi_sum / (int32_t)s_p2_rssi_n));
     printf("   >>> CON TRAFICO PROPIO: %s (%d%% de frames ajenos)\n", v, pct);
 }
 
 static void imprimir_informe(void)
 {
     char b1[18], tmp[16];
     int n_prop = 0, n_aj = 0, n_asoc = 0, n_busc = 0, mi_canal = MI_CANAL;
 
     for (int i = 0; i < s_n_red; i++) {
         if (es_propia(&s_red[i])) { n_prop++; if (s_red[i].canal) mi_canal = s_red[i].canal; }
         else n_aj++;
     }
     for (int i = 0; i < s_n_disp; i++) { if (s_disp[i].red >= 0) n_asoc++; else n_busc++; }
 
     uint32_t f_prop = 0, f_aj = 0;
     int n_mismo = 0, n_solap = 0;
     for (int i = 0; i < s_n_red; i++) {
         const red_t *r = &s_red[i];
         if (!r->canal) continue;
         if (es_propia(r)) { if (r->canal == mi_canal) f_prop += r->frames; continue; }
         int d = abs((int)r->canal - mi_canal);
         if (d == 0) { f_aj += r->frames; n_mismo++; }
         else if (d <= 4) n_solap++;
     }
     uint32_t seg_i = s_listen_ms[mi_canal] / 1000;
     if (seg_i < 1) seg_i = 1;
     uint32_t fps_aj = f_aj / seg_i;
     uint32_t tot = f_prop + f_aj;
     int pct = tot ? (int)(100UL * f_aj / tot) : 0;
 
     printf("#INFORME_INICIO\n");
     printf("==============================================================\n");
     printf(" INFORME DE ENCUESTA WIFI (2.4 GHz) - ESP32-S3\n");
     printf("==============================================================\n");
     printf(" Fase 1 (barrido): %d s | Canales: %d a %d | Escucha por canal: ~%lu s\n",
            DURACION_SEG, CANAL_MIN, CANAL_MAX, (unsigned long)(s_listen_ms[CANAL_MIN] / 1000));
     printf(" Durante el barrido el sensor NO se conecto a ninguna red: solo escucho.\n");
 
     printf("\n [1] RESUMEN\n");
     printf("   Redes detectadas ...... %d  (%d de referencia, %d otras)\n", s_n_red, n_prop, n_aj);
     printf("   Dispositivos vistos ... %d  (con red: %d, buscando red: %d)\n", s_n_disp, n_asoc, n_busc);
     printf("   Frames analizados ..... %lu (gestion: %lu, datos: %lu)\n",
            (unsigned long)s_total_frames, (unsigned long)s_frames_mgmt, (unsigned long)s_frames_data);
 
     printf("\n VEREDICTO DEL AMBIENTE (canal evaluado: %d)\n", mi_canal);
     const char *v;
     if (n_prop) {
         v = pct < 15 ? "LIMPIO" : (pct < 50 ? "MODERADO" : "CONTAMINADO");
         printf("   >>> %s (barrido, sin trafico propio)\n", v);
         printf("   - En el canal %d: %lu frames de tu red y %lu de redes ajenas (%d%% ajenos)\n",
                mi_canal, (unsigned long)f_prop, (unsigned long)f_aj, pct);
         printf("   - Si tu red casi no tiene trafico durante el barrido, el %% de ajenos sube\n");
         printf("     artificialmente: mira la seccion 5 (medicion con ping).\n");
     } else {
         v = fps_aj < 5 ? "LIMPIO" : (fps_aj < 30 ? "MODERADO" : "CONTAMINADO");
         printf("   >>> %s (barrido)\n", v);
         printf("   - Tu red de referencia no se detecto; se mide la ocupacion absoluta del canal.\n");
         printf("   - Canal %d: %lu frames/s de redes que no son la tuya\n", mi_canal, (unsigned long)fps_aj);
         printf("   - Umbrales (orientativos): LIMPIO <5, MODERADO <30, CONTAMINADO >=30 frames/s\n");
     }
     printf("   - Redes ajenas en tu mismo canal: %d\n", n_mismo);
     printf("   - Redes ajenas en canales que se solapan (+-4): %d\n", n_solap);
 
     printf("\n [2] TU RED / TU ROUTER (referencia)\n");
     if (!n_prop) {
         printf("   NO DETECTADA durante la medicion (apagada, fuera de alcance, o sin configurar).\n");
         printf("   El resto del informe sigue siendo valido.\n");
     }
     for (int i = 0; i < s_n_red; i++) {
         const red_t *r = &s_red[i];
         if (!es_propia(r)) continue;
         int a = avg_rssi(r);
         printf("   SSID ........ %s\n", r->ssid_visto ? (r->oculta ? "(oculta)" : r->ssid) : "(sin baliza)");
         printf("   BSSID ....... %s\n", mac_str(r->bssid, b1));
         printf("   Canal ....... %u   Seguridad: %s\n", (unsigned)r->canal, r->ssid_visto ? seg_txt(r->seg) : "?");
         if (r->rssi_n)
             printf("   Senal ....... %d dBm promedio (maximo %d) -> %s\n", a, (int)r->rssi_max, prox_txt(a));
         printf("   Frames ...... %lu   Dispositivos vistos: %u\n", (unsigned long)r->frames, (unsigned)r->n_disp);
         printf("   Dispositivos de esta red:\n");
         printf("      %-17s %-6s %-7s %s\n", "MAC", "dBm", "FRAMES", "TIPO");
         for (int j = 0; j < s_n_disp; j++) {
             const disp_t *d = &s_disp[j];
             if (d->red != i) continue;
             if (d->rssi_n) snprintf(tmp, sizeof(tmp), "%d", (int)(d->rssi_sum / (int32_t)d->rssi_n));
             else snprintf(tmp, sizeof(tmp), "--");
             printf("      %-17s %-6s %-7lu %s\n", mac_str(d->mac, b1), tmp, (unsigned long)d->frames,
                    (d->mac[0] & 2) ? "MAC aleatoria (tipico de celular/PC moderno)" : "MAC fija");
         }
         printf("\n");
     }
 
     printf(" [3] TABLA DE REDES (de mas cerca a mas lejos)\n");
     printf(" %-3s %-20s %-17s %-3s %-5s %-10s %-7s %-4s %s\n",
            "N", "SSID", "BSSID", "CH", "dBm", "SEGURIDAD", "FRAMES", "DISP", "ESTADO");
     int ord[MAX_REDES];
     for (int i = 0; i < s_n_red; i++) {
         int j = i;
         while (j > 0 && avg_rssi(&s_red[ord[j - 1]]) < avg_rssi(&s_red[i])) { ord[j] = ord[j - 1]; j--; }
         ord[j] = i;
     }
     for (int k = 0; k < s_n_red; k++) {
         const red_t *r = &s_red[ord[k]];
         char ch[6], db[8];
         if (r->canal) snprintf(ch, sizeof(ch), "%u", (unsigned)r->canal); else snprintf(ch, sizeof(ch), "?");
         if (r->rssi_n) snprintf(db, sizeof(db), "%d", avg_rssi(r)); else snprintf(db, sizeof(db), "--");
         const char *estado;
         if (es_propia(r)) estado = "TU RED";
         else if (!bssid_cero(MI_BSSID) && memcmp(r->bssid, MI_BSSID, 5) == 0) estado = "posible mismo equipo que tu router";
         else if (r->canal && r->canal == mi_canal) estado = "OTRA - MISMO CANAL";
         else if (r->canal && abs((int)r->canal - mi_canal) <= 4) estado = "OTRA - canal solapado";
         else estado = "OTRA";
         printf(" %-3d %-20.20s %-17s %-3s %-5s %-10s %-7lu %-4u %s\n", k + 1,
                r->ssid_visto ? (r->oculta ? "(oculta)" : r->ssid) : "(sin baliza)",
                mac_str(r->bssid, b1), ch, db, r->ssid_visto ? seg_txt(r->seg) : "?",
                (unsigned long)r->frames, (unsigned)r->n_disp, estado);
     }
 
     printf("\n [4] OCUPACION POR CANAL\n");
     printf("   %-4s %-12s %-7s %-8s %-9s\n", "CH", "SEG ESCUCHA", "REDES", "FRAMES", "FRAMES/S");
     int mejor = 0; uint32_t mejor_fps = 0xFFFFFFFF;
     for (int c = CANAL_MIN; c <= CANAL_MAX; c++) {
         int nr = 0;
         for (int i = 0; i < s_n_red; i++) if (s_red[i].canal == c) nr++;
         uint32_t sc = s_listen_ms[c] / 1000; if (sc < 1) sc = 1;
         uint32_t fps = s_frames_canal[c] / sc;
         if ((c == 1 || c == 6 || c == 11) && fps < mejor_fps) { mejor_fps = fps; mejor = c; }
         printf("   %-4d %-12lu %-7d %-8lu %-9lu%s\n", c, (unsigned long)(s_listen_ms[c] / 1000), nr,
                (unsigned long)s_frames_canal[c], (unsigned long)fps, c == mi_canal ? "  <-- canal evaluado" : "");
     }
     if (mejor) printf("   Canal menos ocupado entre 1, 6 y 11: %d (%lu frames/s)\n", mejor, (unsigned long)mejor_fps);
 
     imprimir_fase2();
 
     printf("\n [6] COMO LEER ESTE INFORME\n");
     printf("   - 'TU RED' es la referencia configurada en el codigo (opcional). Todo lo demas\n");
     printf("     es 'OTRA'. 'posible mismo equipo' = BSSID casi igual al tuyo (red de invitados).\n");
     printf("   - El nombre (SSID) sale de las balizas. '(oculta)' = la red no lo anuncia; se\n");
     printf("     revela si algun dispositivo cercano la consulta durante la medicion.\n");
     printf("   - '(sin baliza)' = se vieron frames pero nunca la baliza (senal muy debil): sin nombre.\n");
     printf("   - dBm: cuanto mas cerca de 0, mas fuerte (-30 muy fuerte, -90 casi inaudible).\n");
     printf("     La distancia es orientativa: paredes y muebles la alteran.\n");
     printf("   - Un solo sensor NO da la posicion exacta de un router, solo cercania. Para\n");
     printf("     ubicarlo: MODO_BUSCAR 1 con su BSSID en OBJETIVO_BSSID, y camina con la placa.\n");
     printf("   - Fase 1: FRAMES es una MUESTRA (el sensor salta de canal). Fase 2: el sensor se\n");
     printf("     conecta a tu router y le hace ping, como en la prueba CSI, y mide solo ese canal.\n");
     printf("   - Solo se registran metadatos. No se guarda contenido ni se listan MAC de\n");
     printf("     dispositivos ajenos (solo cuantos hay).\n");
     printf("   - Redes de 5 GHz no se ven: el ESP32-S3 opera solo en 2.4 GHz.\n");
     if (s_desc_redes || s_desc_disp)
         printf("   - AVISO: tablas llenas, se descartaron %lu redes y %lu dispositivos.\n",
                (unsigned long)s_desc_redes, (unsigned long)s_desc_disp);
     printf("#INFORME_FIN\n");
     fflush(stdout);
 }
 
 /* ---------- modo buscar: localizar CUALQUIER red por su BSSID ---------- */
 static void modo_buscar(void)
 {
     char b1[18];
     printf("#BUSCAR_INICIO\n");
     printf("MODO BUSCAR: red objetivo %s\n", mac_str(OBJETIVO_BSSID, b1));
     printf("Camina con la placa: el valor mas alto (cercano a 0 dBm) = mas cerca de esa red.\n");
     while (1) {
         int ch = CANAL_MIN;
         printf("Buscando la red en los canales %d a %d...\n", CANAL_MIN, CANAL_MAX);
         while (1) {
             esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
             s_loc_sum = 0; s_loc_n = 0;
             vTaskDelay(pdMS_TO_TICKS(400));
             if (s_loc_n > 0) break;
             ch = (ch >= CANAL_MAX) ? CANAL_MIN : ch + 1;
         }
         printf("Red encontrada en el canal %d.\n", ch);
         int sin_senal = 0;
         while (sin_senal < 5) {
             vTaskDelay(pdMS_TO_TICKS(1000));
             int32_t sum = s_loc_sum; uint32_t n = s_loc_n;
             s_loc_sum = 0; s_loc_n = 0;
             if (n == 0) { sin_senal++; printf("sin senal...\n"); continue; }
             sin_senal = 0;
             int rssi = (int)(sum / (int32_t)n);
             int barras = (rssi + 90) * 20 / 60;
             if (barras < 0) barras = 0;
             if (barras > 20) barras = 20;
             char barra[21];
             for (int i = 0; i < 20; i++) barra[i] = i < barras ? '#' : '-';
             barra[20] = 0;
             printf("%4d dBm  [%s]  %s\n", rssi, barra, prox_txt(rssi));
         }
         printf("Se perdio la senal. Buscando de nuevo.\n");
     }
 }
 
 /* ---------- principal ---------- */
 void app_main(void)
 {
     esp_log_level_set("*", ESP_LOG_NONE);                /* silencio: solo sale el informe */
 
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
     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));  /* fase 1: sin conexion a ninguna red */
     ESP_ERROR_CHECK(esp_wifi_start());
 
     wifi_promiscuous_filter_t filt = {
         .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
     };
     ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
     ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_cb));
     ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
 
     if (MODO_BUSCAR) modo_buscar();                      /* no vuelve */
 
     printf("#ENCUESTA_INICIO %d\n", DURACION_SEG);
     fflush(stdout);
     int64_t t0 = esp_timer_get_time();
     int ch = CANAL_MIN;
     while ((esp_timer_get_time() - t0) < (int64_t)DURACION_SEG * 1000000LL) {
         esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
         vTaskDelay(pdMS_TO_TICKS(DWELL_MS));
         s_listen_ms[ch] += DWELL_MS;
         ch = (ch >= CANAL_MAX) ? CANAL_MIN : ch + 1;
     }
     esp_wifi_set_promiscuous(false);
     vTaskDelay(pdMS_TO_TICKS(200));
 
     if (PING_ACTIVO) fase2_ejecutar();                   /* conecta, pingea y mide */
 
     imprimir_informe();
     while (1) vTaskDelay(pdMS_TO_TICKS(1000));           /* RESET para repetir */
 }