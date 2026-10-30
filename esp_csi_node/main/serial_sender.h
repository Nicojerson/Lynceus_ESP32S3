// serial_sender.h
#pragma once
#include <stdint.h>
#include <stddef.h>
int serial_sender_init(void);
int serial_sender_send(const uint8_t *buf, size_t len);  // >0 = ok, -1 = descartado