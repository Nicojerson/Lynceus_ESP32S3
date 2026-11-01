#!/usr/bin/env python3
import argparse
import binascii
import datetime
import socket
import struct
import sys
import time
import numpy as np
import serial
from serial.tools import list_ports

# ---- CONFIGURACION: editar aca ------------------------------------------------
PUERTO = "COM13"      # puerto COM del conversor USB-serie donde esta conectado el ESP32
BAUD = 460800       # debe coincidir con SER_BAUD de serial_sender.c
# ------------------------------------------------------------------------------

SYNC = b"\xA5\x5A"
MAX_PAYLOAD = 2048
CSI_MAGIC = 0xC5110001
HDR_FMT = "<IBBHIIbbBB"      # magic, nodo, antenas, subportadoras, MHz, seq, rssi, ruido, ppdu, flags
HDR_LEN = 20

class Deframer:
    """Convierte el flujo de bytes del puerto serie en tramas validas."""

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
            n, t_us = struct.unpack_from("<HI", self.buf, 2)
            if n == 0 or n > MAX_PAYLOAD:
                self.junk += 2
                del self.buf[:2]
                continue
            total = 8 + n + 2
            if len(self.buf) < total:
                break
            crc_rx = struct.unpack_from("<H", self.buf, 8 + n)[0]
            if binascii.crc_hqx(bytes(self.buf[2:8 + n]), 0xFFFF) == crc_rx:
                out.append((t_us, bytes(self.buf[8:8 + n])))
                del self.buf[:total]
            else:
                self.bad_crc += 1
                del self.buf[:2]          # falso sync: seguir buscando justo despues
        return out

def parse_csi(payload):
    """Devuelve un dict con el frame CSI, o None si el payload no es un frame CSI valido."""
    if len(payload) < HDR_LEN:
        return None
    magic, nodo, nant, nsub, freq, seq, rssi, ruido, ppdu, flags = struct.unpack_from(HDR_FMT, payload, 0)
    if magic != CSI_MAGIC:
        return None                        # por ejemplo, el paquete de sincronizacion (0xC511A110)
    iq = payload[HDR_LEN:]
    if nant == 0 or nsub == 0 or len(iq) != nant * nsub * 2:
        return None
    raw = np.frombuffer(iq, dtype=np.int8).astype(np.float32)
    z = (raw[1::2] + 1j * raw[0::2]).reshape(nant, nsub)[0]     # ESP-IDF entrega [imag, real]
    return dict(nodo=nodo, nsub=nsub, freq=freq, seq=seq, rssi=rssi, ruido=ruido, flags=flags, z=z)

def listar_puertos():
    puertos = [p for p in list_ports.comports() if "BTHENUM" not in (p.hwid or "")]
    if not puertos:
        print("No hay puertos serie USB. Revisa el cable, el puerto de la placa y el driver.")
        return
    print("Puertos disponibles:\n")
    for p in puertos:
        if p.vid == 0x303A:
            tipo = "USB nativo del ESP32-S3 (lleva los LOGS, no los datos)"
        elif p.vid in (0x1A86, 0x10C4, 0x0403):
            tipo = "conversor USB-serie (puerto rotulado COM): es el de DATOS"
        else:
            tipo = "no identificado"
        print(f"  {p.device:8s} {p.description}\n           {p.hwid}\n           -> {tipo}\n")
    print("Corre de nuevo con:  python csi_receiver.py --port COMx")

def diagnostico(n_bytes, tail, hb, ok_seen):
    if n_bytes == 0:
        return ("SIN BYTES en este intervalo. Revisa: (1) que sea el puerto rotulado COM y no el USB, "
                "(2) que ningun otro programa (monitor, otro script) tenga abierto el puerto, "
                "(3) apretar RESET en la placa con este script ya corriendo. "
                "Si al apretar RESET llega el texto 'ESP-ROM' pero despues nada, "
                "el firmware no esta sacando bytes por UART0.")
    imprimible = sum(1 for b in tail if 32 <= b < 127 or b in (10, 13)) / max(1, len(tail))
    if ok_seen:
        return ("Llego 'SERIAL OK': el UART0 de la placa SI llega a esta compu. "
                "Si no aparecen tramas, el problema esta en el flujo de frames, no en el cable.")
    if hb:
        return ("Llega el latido 'HB' pero no tramas: el cable funciona, el firmware no esta enviando frames CSI "
                "(sin WiFi conectado, o ningun frame supera el filtro).")
    if imprimible > 0.8:
        return ("Llega TEXTO (logs de la placa), no tramas: este puerto lleva la consola. "
                "Usa el otro puerto, o revisa que la consola este configurada en USB Serial/JTAG.")
    return ("Llegan bytes sin formato: velocidad (baud) distinta entre firmware y receptor, o ruido. "
            "Verifica SER_BAUD en serial_sender.c y --baud aca.")

def main():
    ap = argparse.ArgumentParser(description="Receptor de CSI por serie")
    ap.add_argument("--port", default=PUERTO, help="puerto COM (por defecto el de PUERTO arriba)")
    ap.add_argument("--list", action="store_true", help="solo listar los puertos disponibles")
    ap.add_argument("--baud", type=int, default=BAUD, help="debe coincidir con SER_BAUD del firmware")
    ap.add_argument("--raw", action="store_true", help="solo vuelca los bytes recibidos (diagnostico)")
    ap.add_argument("--udp", help="reenviar cada frame CSI por UDP, formato ip:puerto")
    ap.add_argument("--out", default="", help="nombre del .npz de salida")
    ap.add_argument("--seconds", type=float, default=0, help="parar solo a los N segundos (0 = hasta Ctrl+C)")
    args = ap.parse_args()

    if args.list or not args.port:
        listar_puertos()
        return

    ser = serial.Serial()
    ser.port, ser.baudrate, ser.timeout = args.port, args.baud, 0.1
    ser.dtr = ser.rts = False              # evita que Windows resetee la placa al abrir
    try:
        ser.open()
    except serial.SerialException as e:
        print(f"No se pudo abrir {args.port}: {e}")
        print("Cierra cualquier monitor u otro script que use ese puerto y revisa el numero de COM.")
        return

    udp = dest = None
    if args.udp:
        host, port = args.udp.rsplit(":", 1)
        dest = (host, int(port))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Escuchando {args.port} a {args.baud} baud. Ctrl+C para parar. "
          f"Si no ves nada, apreta RESET en la placa con esto ya corriendo.\n")

    dfr = Deframer()
    t_list, seq_list, rssi_list, csi_list = [], [], [], []
    nsub_ref = None
    last_t = None
    t_off = 0
    last_seq = None
    lost = otros = otro_tam = 0
    tail = b""
    hb = ok_seen = 0
    # contadores del intervalo
    i_bytes = i_frames = 0
    last_rssi = None
    t0 = t_int = time.time()

    try:
        while True:
            data = ser.read(max(1, ser.in_waiting))
            now = time.time()
            if data:
                i_bytes += len(data)
                tail = (tail + data)[-64:]
                hb += data.count(b"HB\r\n")
                ok_seen += data.count(b"SERIAL OK")
                if args.raw:
                    print(f"{now - t0:7.2f}s {len(data):5d} B | {data[:32].hex(' ')}")
                else:
                    for t_us, payload in dfr.feed(data):
                        f = parse_csi(payload)
                        if f is None:
                            otros += 1
                            continue
                        if nsub_ref is None:
                            nsub_ref = f["nsub"]
                        if f["nsub"] != nsub_ref:
                            otro_tam += 1
                            continue
                        if last_t is not None and t_us < last_t:
                            t_off += 1 << 32              # el contador de 32 bits dio la vuelta
                        last_t = t_us
                        if last_seq is not None and f["seq"] > last_seq + 1:
                            lost += f["seq"] - last_seq - 1
                        last_seq = f["seq"]
                        t_list.append((t_us + t_off) / 1e6)
                        seq_list.append(f["seq"])
                        rssi_list.append(f["rssi"])
                        csi_list.append(f["z"])
                        i_frames += 1
                        last_rssi = f["rssi"]
                        if udp:
                            # CAMBIO: antes era udp.sendto(payload, dest). Ahora se antepone el tiempo del ESP32
                            # (8 bytes, double, segundos) para que csi_presencia.py pueda remuestrear.
                            udp.sendto(struct.pack("<d", t_list[-1]) + payload, dest)

            if not args.raw and now - t_int >= 2.0:
                dt = now - t_int
                if i_frames:
                    print(f"[{now - t0:5.0f}s] CSI {i_frames / dt:5.1f}/s | RSSI {last_rssi:4d} dBm | "
                          f"subport {nsub_ref} | "
                          f"huecos(seq) {lost} | CRC malos {dfr.bad_crc} | otros {otros} | "
                          f"otro tamano {otro_tam} | {i_bytes / dt:5.0f} B/s")
                else:
                    print(f"[{now - t0:5.0f}s] sin frames CSI | {i_bytes / dt:5.0f} B/s | "
                          f"HB {hb} | CRC malos {dfr.bad_crc}")
                    print("   -> " + diagnostico(i_bytes, tail, hb, ok_seen))
                i_bytes = i_frames = 0
                t_int = now

            if args.seconds and now - t0 >= args.seconds:
                break
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()

    if t_list:
        nombre = args.out or datetime.datetime.now().strftime("csi_%Y%m%d_%H%M%S.npz")
        np.savez(nombre,
                 t_s=np.array(t_list, dtype=np.float64),
                 seq=np.array(seq_list, dtype=np.uint32),
                 rssi=np.array(rssi_list, dtype=np.int8),
                 csi=np.array(csi_list, dtype=np.complex64))
        dur = t_list[-1] - t_list[0]
        print(f"\nGuardados {len(t_list)} frames ({dur:.0f} s, {len(t_list) / max(dur, 1e-9):.1f} fps) en {nombre}")
        print("Leer despues:  d = np.load('%s'); d['csi'].shape, d['t_s']" % nombre)
    elif not args.raw:
        print("\nNo se recibio ningun frame CSI valido, no se guardo nada.")

if __name__ == "__main__":
    main()