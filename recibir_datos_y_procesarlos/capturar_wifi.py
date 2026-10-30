#!/usr/bin/env python3
"""
capturar_wifi.py - Guarda en un archivo .bin TODO lo que manda el firmware wifi_capture por el cable.

Uso:
    python capturar_wifi.py                       -> usa PUERTO y BAUD de abajo
    python capturar_wifi.py --port COM6 --baud 921600
    python capturar_wifi.py --list                -> lista los puertos

Apreta RESET en la placa con esto corriendo. Se detiene solo cuando la placa termina
(o con Ctrl+C) y deja un archivo  wifi_AAAAMMDD_HHMMSS.bin  en la carpeta actual.
Despues:  python analizar_wifi.py wifi_XXXX.bin

El .bin guarda cada trama valida EXACTAMENTE como llego (sin interpretar nada), precedida de
una cabecera de 24 bytes: 'LYNWCAP1' | version u32 | hora de la PC (unix, f64) | baud u32.
Requiere: pip install pyserial
"""
import argparse
import binascii
import datetime
import struct
import sys
import time

import serial
from serial.tools import list_ports

# ---- CONFIGURACION: editar aca -----------------------------------------------
PUERTO = "COM13"       # puerto COM del conversor USB-serie (el rotulado COM)
BAUD = 921600         # debe coincidir con SER_BAUD del firmware
# ------------------------------------------------------------------------------

SYNC = b"\xA5\x5A"
MAGIC = b"LYNWCAP1"
MAX_PAYLOAD = 2048
EV_STATS, EV_END, EV_FASE, EV_CANAL = 5, 6, 3, 2


class Deframer:
    def __init__(self):
        self.buf = bytearray()
        self.bad_crc = 0
        self.junk = 0

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            i = self.buf.find(SYNC)
            if i < 0:
                keep = 1 if self.buf.endswith(b"\xA5") else 0
                self.junk += len(self.buf) - keep
                del self.buf[:len(self.buf) - keep]
                break
            if i > 0:
                self.junk += i
                del self.buf[:i]
            if len(self.buf) < 8:
                break
            n = struct.unpack_from("<H", self.buf, 2)[0]
            if n == 0 or n > MAX_PAYLOAD:
                self.junk += 2
                del self.buf[:2]
                continue
            total = 8 + n + 2
            if len(self.buf) < total:
                break
            crc_rx = struct.unpack_from("<H", self.buf, 8 + n)[0]
            if binascii.crc_hqx(bytes(self.buf[2:8 + n]), 0xFFFF) == crc_rx:
                out.append(bytes(self.buf[:total]))
                del self.buf[:total]
            else:
                self.bad_crc += 1
                del self.buf[:2]
        return out


def main():
    ap = argparse.ArgumentParser(description="Captura cruda del sniffer WiFi")
    ap.add_argument("--port", default=PUERTO)
    ap.add_argument("--baud", type=int, default=BAUD)
    ap.add_argument("--out", default="", help="nombre del .bin de salida")
    ap.add_argument("--seconds", type=float, default=0, help="parar a los N segundos (0 = hasta que termine la placa)")
    ap.add_argument("--list", action="store_true", help="solo listar puertos")
    args = ap.parse_args()

    if args.list:
        for p in list_ports.comports():
            if "BTHENUM" not in (p.hwid or ""):
                print(f"  {p.device:8s} {p.description}   {p.hwid}")
        return

    ser = serial.Serial()
    ser.port, ser.baudrate, ser.timeout = args.port, args.baud, 0.1
    ser.dtr = ser.rts = False
    try:
        ser.open()
    except serial.SerialException as e:
        print(f"No se pudo abrir {args.port}: {e}")
        print("Cierra cualquier monitor u otro script que use ese puerto y revisa el numero de COM.")
        return

    nombre = args.out or datetime.datetime.now().strftime("wifi_%Y%m%d_%H%M%S.bin")
    f = open(nombre, "wb")
    f.write(MAGIC + struct.pack("<IdI", 1, time.time(), args.baud))
    print(f"Escuchando {args.port} a {args.baud} baud -> {nombre}")
    print("Apreta RESET en la placa. Ctrl+C para parar.\n")

    d = Deframer()
    n_reg = n_frames = i_reg = i_bytes = 0
    fase = canal = 0
    st = None
    terminado = False
    t0 = t_int = time.time()
    try:
        while not terminado:
            data = ser.read(max(1, ser.in_waiting))
            now = time.time()
            i_bytes += len(data)
            for raw in d.feed(data):
                f.write(raw)
                n_reg += 1
                i_reg += 1
                p = raw[8:-2]
                if p[0] == 1:
                    n_frames += 1
                elif p[0] == 2 and len(p) >= 2:
                    if p[1] == EV_STATS and len(p) >= 16:
                        st = struct.unpack_from("<III", p, 2)
                        fase, canal = p[14], p[15]
                    elif p[1] == EV_END:
                        terminado = True
            if now - t_int >= 2.0:
                dt = now - t_int
                perd = ""
                if st and st[0]:
                    perd = f" | placa: {st[0]} frames oidos, {st[2]} registros perdidos ({100.0 * st[2] / max(1, st[1] + st[2]):.1f}%)"
                if i_reg:
                    print(f"[{now - t0:5.0f}s] fase {fase} canal {canal:2d} | {i_reg / dt:6.0f} reg/s | "
                          f"{i_bytes / dt / 1000:5.1f} kB/s | CRC malos {d.bad_crc}{perd}")
                else:
                    print(f"[{now - t0:5.0f}s] sin registros ({i_bytes} bytes). Apreta RESET en la placa; "
                          f"revisa el COM y el baud ({args.baud}).")
                i_reg = i_bytes = 0
                t_int = now
            if args.seconds and now - t0 >= args.seconds:
                break
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()
        f.close()

    print(f"\nGuardados {n_reg} registros ({n_frames} frames WiFi), CRC malos {d.bad_crc}, bytes descartados {d.junk}")
    if terminado:
        print("La placa termino la captura.")
    else:
        print("Aviso: se corto antes de que la placa terminara (el informe de fase 2 puede faltar).")
    print(f"Archivo: {nombre}\nAnalizar:  python analizar_wifi.py {nombre}")


if __name__ == "__main__":
    main()