// serial_sender.c  -  salida de frames CSI por UART0 (puerto rotulado COM de la placa)
//
// Cambios respecto de la version anterior:
//   * uart_set_pin() fija explicitamente GPIO43 (TX) y GPIO44 (RX) del UART0 del ESP32-S3.
//     Antes usaba UART_PIN_NO_CHANGE y, con la consola movida a USB Serial/JTAG, el TX podia
//     no quedar conectado al pin.
//   * Escribe "SERIAL OK" apenas inicia el UART, para comprobar el camino fisico.
//   * Sigue mandando "HB" cada segundo SOLO cuando no hay frames para enviar.
#include "serial_sender.h"
#include <string.h>
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "esp_timer.h"
#include "esp_log.h"

#define SER_UART        UART_NUM_0
#define SER_TX_PIN      43              // UART0 TX en ESP32-S3 (va al conversor USB-serie)
#define SER_RX_PIN      44              // UART0 RX
#define SER_BAUD        460800           // debe coincidir con --baud del receptor
#define SER_MAX_PAYLOAD 1024
#define SER_BUF_SZ      (16 * 1024)

static const char *TAG = "serial_sender";
static StreamBufferHandle_t s_sb;
static SemaphoreHandle_t s_mtx;
static uint32_t s_dropped;

static uint16_t crc16_ccitt(uint16_t c, const uint8_t *d, size_t n)
{
    while (n--) {
        c ^= (uint16_t)(*d++) << 8;
        for (int i = 0; i < 8; i++) c = (c & 0x8000) ? (c << 1) ^ 0x1021 : (c << 1);
    }
    return c;
}

static void writer_task(void *arg)
{
    static uint8_t chunk[512];
    for (;;) {
        size_t n = xStreamBufferReceive(s_sb, chunk, sizeof(chunk), pdMS_TO_TICKS(1000));
        if (n) uart_write_bytes(SER_UART, chunk, n);
        else   uart_write_bytes(SER_UART, "HB\r\n", 4);   // latido de prueba (se borra despues)
    }
}

int serial_sender_init(void)
{
    uart_config_t cfg = {
        .baud_rate = SER_BAUD, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_driver_install(SER_UART, 256, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(SER_UART, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(SER_UART, SER_TX_PIN, SER_RX_PIN,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    uart_write_bytes(SER_UART, "SERIAL OK\r\n", 11);       // prueba del camino fisico

    s_sb  = xStreamBufferCreate(SER_BUF_SZ, 1);
    s_mtx = xSemaphoreCreateMutex();
    xTaskCreate(writer_task, "ser_tx", 3072, NULL, 5, NULL);
    ESP_LOGI(TAG, "serial sender listo (%d baud, TX=GPIO%d)", SER_BAUD, SER_TX_PIN);
    return 0;
}

int serial_sender_send(const uint8_t *buf, size_t len)
{
    if (!s_sb || len == 0 || len > SER_MAX_PAYLOAD) return -1;
    if (xSemaphoreTake(s_mtx, 0) != pdTRUE) return -1;      // nunca bloquear el callback

    size_t need = 8 + len + 2;
    if (xStreamBufferSpacesAvailable(s_sb) < need) {         // todo o nada
        s_dropped++;
        xSemaphoreGive(s_mtx);
        return -1;
    }
    uint8_t hdr[8] = {0xA5, 0x5A};
    uint16_t l = (uint16_t)len;
    uint32_t t = (uint32_t)esp_timer_get_time();             // timestamp del ESP32 (us)
    memcpy(&hdr[2], &l, 2);
    memcpy(&hdr[4], &t, 4);

    uint16_t crc = crc16_ccitt(0xFFFF, &hdr[2], 6);          // CRC sobre largo+tiempo+payload
    crc = crc16_ccitt(crc, buf, len);

    xStreamBufferSend(s_sb, hdr, 8, 0);
    xStreamBufferSend(s_sb, buf, len, 0);
    xStreamBufferSend(s_sb, &crc, 2, 0);
    xSemaphoreGive(s_mtx);
    return (int)len;
}