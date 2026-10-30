#!/usr/bin/env python3
"""
analizar_wifi.py - Analiza una captura .bin del sniffer WiFi y genera el informe de encuesta.

Uso:
    python analizar_wifi.py wifi_20261026_120000.bin            -> informe en pantalla y en un .txt
    python analizar_wifi.py wifi_XXXX.bin --csv                  -> ademas exporta los frames y eventos a CSV
    python analizar_wifi.py wifi_XXXX.bin --sin-txt              -> solo en pantalla

El analisis es el mismo que hacia el firmware wifi_survey, pero ahora en la PC: se puede repetir
sobre el mismo archivo cambiando la red de referencia (MI_BSSID / MI_SSID / MI_CANAL) aca abajo.
Solo necesita Python 3 (sin librerias externas).
"""
import argparse
import binascii
import csv
import os
import struct
import sys

# ===================== CONFIGURACION (tu red de referencia, opcional) =====================
MI_BSSID = bytes.fromhex("f8d1112db96e")   # para no usar ninguna: bytes(6)  y  MI_SSID = ""
MI_SSID = "TP-LINK_Lynceus"
MI_CANAL = 6
# ==========================================================================================

SYNC = b"\xA5\x5A"
MAGIC = b"LYNWCAP1"
REG_FRAME, REG_EVENTO = 1, 2
EV_START, EV_CANAL, EV_FASE, EV_P2, EV_STATS, EV_END = 1, 2, 3, 4, 5, 6
FRAME_HDR = struct.Struct("<BBBBbbBBBBIHH")     # 18 bytes
TIPOS_PKT = {0: "MGMT", 1: "CTRL", 2: "DATA", 3: "MISC"}
SEG_TXT = ["ABIERTA", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3"]


def cdiv(a, b):
    """Division entera como en C (trunca hacia cero)."""
    return int(a / b)


def mac_str(m):
    return ":".join("%02x" % x for x in m)


def prox_txt(rssi):
    if rssi >= -40: return "MUY CERCA (~1-2 m)"
    if rssi >= -55: return "CERCA (pocos metros)"
    if rssi >= -70: return "MEDIA (otra habitacion / 5-15 m)"
    if rssi >= -80: return "LEJOS"
    return "MUY LEJOS (borde de deteccion)"


# ---------------------------------------------------------------- lectura del .bin
def leer_registros(ruta):
    """Genera (t_s, payload) por cada trama valida del archivo. t_s = reloj del ESP32 sin saltos."""
    with open(ruta, "rb") as f:
        datos = f.read()
    if datos[:8] != MAGIC:
        raise SystemExit(f"{ruta} no parece una captura de capturar_wifi.py (cabecera incorrecta).")
    i = 24
    off, last = 0, None
    malos = 0
    while i + 10 <= len(datos):
        if datos[i:i + 2] != SYNC:
            j = datos.find(SYNC, i + 1)
            if j < 0: break
            i = j
            continue
        n, t_us = struct.unpack_from("<HI", datos, i + 2)
        fin = i + 8 + n + 2
        if fin > len(datos): break
        crc = struct.unpack_from("<H", datos, i + 8 + n)[0]
        if binascii.crc_hqx(datos[i + 2:i + 8 + n], 0xFFFF) != crc:
            malos += 1
            i += 2
            continue
        if last is not None and t_us < last - (1 << 31):
            off += 1 << 32
        last = t_us
        yield (t_us + off) / 1e6, datos[i + 8:i + 8 + n]
        i = fin
    if malos:
        print(f"Aviso: {malos} tramas con CRC malo en el archivo (ignoradas).", file=sys.stderr)


class Frame:
    __slots__ = ("t", "fase", "pkt", "canal", "rssi", "noise", "rate", "flags", "mcs", "rxts", "sig_len", "data")


def decodificar_frame(t, p):
    if len(p) < 18:
        return None
    (_, fase, pkt, canal, rssi, noise, rate, flags, mcs, _r, rxts, sig_len, stored) = FRAME_HDR.unpack_from(p, 0)
    fr = Frame()
    fr.t, fr.fase, fr.pkt, fr.canal, fr.rssi, fr.noise = t, fase, pkt, canal, rssi, noise
    fr.rate, fr.flags, fr.mcs, fr.rxts, fr.sig_len = rate, flags, mcs, rxts, sig_len
    fr.data = p[18:18 + stored]
    return fr


# ---------------------------------------------------------------- estructuras del analisis
class Red:
    def __init__(self, bssid):
        self.bssid = bssid
        self.ssid = ""
        self.ssid_visto = False
        self.oculta = False
        self.canal = 0
        self.seg = 0
        self.seg_ok = False
        self.frames = self.f_mgmt = self.f_data = self.beacons = 0
        self.rssi_sum = self.rssi_n = 0
        self.rssi_max = -127
        self.n_disp = 0

    def avg(self):
        return cdiv(self.rssi_sum, self.rssi_n) if self.rssi_n else -127


class Disp:
    def __init__(self, mac, red):
        self.mac, self.red = mac, red
        self.frames = self.rssi_sum = self.rssi_n = 0


def es_propia(r):
    if any(MI_BSSID) and r.bssid == MI_BSSID:
        return True
    if MI_SSID and r.ssid_visto and not r.oculta and r.ssid == MI_SSID:
        return True
    return False


def rsn_akm(ie):
    """Devuelve (hay_sae, hay_otro) a partir del elemento RSN."""
    l = len(ie)
    sae = otro = False
    if l < 10: return sae, otro
    off = 6
    pc = ie[off] | (ie[off + 1] << 8)
    off += 2 + 4 * pc
    if off + 2 > l: return sae, otro
    ac = ie[off] | (ie[off + 1] << 8)
    off += 2
    for _ in range(ac):
        if off + 4 > l: break
        if ie[off] == 0x00 and ie[off + 1] == 0x0F and ie[off + 2] == 0xAC and ie[off + 3] in (8, 9):
            sae = True
        else:
            otro = True
        off += 4
    return sae, otro


def parsear_baliza(r, f, ln, canal_rx):
    """Mismo analisis que el firmware. f = bytes guardados; ln = largo real del frame sin FCS."""
    if ln < 36 or len(f) < 36:
        return
    truncado = len(f) < ln
    privacy = bool((f[34] | (f[35] << 8)) & 0x0010)
    rsn = sae = otro = wpa = False
    canal_ds = 0
    p, end = 36, min(ln, len(f))
    while p + 2 <= end:
        id_, l = f[p], f[p + 1]
        if p + 2 + l > end: break
        d = f[p + 2:p + 2 + l]
        if id_ == 0:
            if not any(d):
                if not r.ssid: r.oculta = True
            else:
                r.ssid = "".join(chr(c) if 32 <= c < 127 else "?" for c in d[:32])
                r.oculta = False
            r.ssid_visto = True
        elif id_ == 3 and l == 1:
            canal_ds = d[0]
        elif id_ == 48:
            rsn = True
            sae, otro = rsn_akm(d)
        elif id_ == 221 and l >= 4 and d[0] == 0x00 and d[1] == 0x50 and d[2] == 0xF2 and d[3] == 0x01:
            wpa = True
        p += 2 + l
    r.canal = canal_ds if canal_ds else (r.canal if r.canal else canal_rx)
    # una baliza cortada puede no llegar a mostrar el RSN: no pisar una seguridad ya conocida
    if rsn or wpa or not truncado or not r.seg_ok:
        if rsn:        r.seg = 5 if (sae and otro) else (4 if sae else 3)
        elif wpa:      r.seg = 2
        elif privacy:  r.seg = 1
        else:          r.seg = 0
        r.seg_ok = rsn or wpa or not truncado


class Analisis:
    def __init__(self):
        self.redes, self.idx_red = [], {}
        self.disp, self.idx_disp = [], {}
        self.total = self.f_mgmt = self.f_data = 0
        self.frames_canal = [0] * 16
        self.listen_ms = [0] * 16
        self.p2_prop = self.p2_aj = self.p2_rssi_n = self.p2_rssi_sum = 0
        self.p2_bssid = None
        self.n_frames_total = 0
        self.fases_vistas = set()

    def buscar_red(self, bssid):
        i = self.idx_red.get(bssid)
        if i is None:
            i = len(self.redes)
            self.redes.append(Red(bssid))
            self.idx_red[bssid] = i
        return i

    def buscar_disp(self, mac, red):
        i = self.idx_disp.get(mac)
        if i is not None:
            d = self.disp[i]
            if d.red < 0 and red >= 0:
                d.red = red
                self.redes[red].n_disp += 1
            return d
        d = Disp(mac, red)
        self.idx_disp[mac] = len(self.disp)
        self.disp.append(d)
        if red >= 0:
            self.redes[red].n_disp += 1
        return d

    def frame(self, fr):
        self.n_frames_total += 1
        self.fases_vistas.add(fr.fase)
        if fr.pkt not in (0, 2):
            return
        f = fr.data
        ln = fr.sig_len
        if ln > 4: ln -= 4
        if ln < 24 or len(f) < 22:
            return
        rssi, canal_rx = fr.rssi, fr.canal
        tipo, subtipo = (f[0] >> 2) & 3, (f[0] >> 4) & 15
        to_ds, from_ds = bool(f[1] & 1), bool(f[1] & 2)
        a1, a2, a3 = bytes(f[4:10]), bytes(f[10:16]), bytes(f[16:22])

        bssid = estacion = None
        est_tx = sin_red = False
        if tipo == 0:
            if subtipo == 4:
                sin_red, estacion, est_tx = True, a2, True
            else:
                bssid = a3
                if subtipo <= 3 or subtipo == 11:
                    if a2 == a3: estacion = a1
                    else: estacion, est_tx = a2, True
        elif tipo == 2:
            if to_ds and from_ds: return
            if not to_ds and not from_ds: bssid = a3
            elif to_ds: bssid, estacion, est_tx = a1, a2, True
            else: bssid, estacion = a2, a1
        else:
            return
        if not sin_red and (bssid[0] & 1):
            return

        if fr.fase == 2:                      # fase con ping: solo contadores propios
            if not sin_red and self.p2_bssid is not None:
                if bssid == self.p2_bssid:
                    self.p2_prop += 1
                    if a2 == bssid:
                        self.p2_rssi_sum += rssi
                        self.p2_rssi_n += 1
                else:
                    self.p2_aj += 1
            return

        self.total += 1
        if tipo == 0: self.f_mgmt += 1
        else: self.f_data += 1
        if 1 <= canal_rx <= 14: self.frames_canal[canal_rx] += 1

        if sin_red:
            if not (estacion[0] & 1):
                self.buscar_disp(estacion, -1).frames += 1
            return

        ri = self.buscar_red(bssid)
        r = self.redes[ri]
        if r.canal == 0: r.canal = canal_rx
        r.frames += 1
        if tipo == 0: r.f_mgmt += 1
        else: r.f_data += 1

        if a2 == bssid:
            r.rssi_sum += rssi
            r.rssi_n += 1
            if rssi > r.rssi_max: r.rssi_max = rssi
            if tipo == 0 and subtipo in (8, 5):
                if subtipo == 8: r.beacons += 1
                parsear_baliza(r, f, ln, canal_rx)

        if estacion is not None and not (estacion[0] & 1) and estacion != bssid:
            d = self.buscar_disp(estacion, ri)
            d.frames += 1
            if est_tx:
                d.rssi_sum += rssi
                d.rssi_n += 1


# ---------------------------------------------------------------- informe
def generar_informe(a, cfg, p2, stats, tam_archivo):
    L = []
    P = L.append
    CANAL_MIN, CANAL_MAX = cfg["ch_min"], cfg["ch_max"]
    n_prop = n_aj = n_asoc = n_busc = 0
    mi_canal = MI_CANAL
    for r in a.redes:
        if es_propia(r):
            n_prop += 1
            if r.canal: mi_canal = r.canal
        else:
            n_aj += 1
    for d in a.disp:
        if d.red >= 0: n_asoc += 1
        else: n_busc += 1

    f_prop = f_aj = n_mismo = n_solap = 0
    for r in a.redes:
        if not r.canal: continue
        if es_propia(r):
            if r.canal == mi_canal: f_prop += r.frames
            continue
        dd = abs(r.canal - mi_canal)
        if dd == 0:
            f_aj += r.frames
            n_mismo += 1
        elif dd <= 4:
            n_solap += 1
    seg_i = max(1, a.listen_ms[mi_canal] // 1000)
    fps_aj = f_aj // seg_i
    tot = f_prop + f_aj
    pct = (100 * f_aj // tot) if tot else 0

    P("==============================================================")
    P(" INFORME DE ENCUESTA WIFI (2.4 GHz) - ESP32-S3")
    P("==============================================================")
    P(" Fase 1 (barrido): %d s | Canales: %d a %d | Escucha por canal: ~%d s" %
      (cfg["dur"], CANAL_MIN, CANAL_MAX, a.listen_ms[CANAL_MIN] // 1000))
    P(" Durante el barrido el sensor NO se conecto a ninguna red: solo escucho.")

    P("\n [1] RESUMEN")
    P("   Redes detectadas ...... %d  (%d de referencia, %d otras)" % (len(a.redes), n_prop, n_aj))
    P("   Dispositivos vistos ... %d  (con red: %d, buscando red: %d)" % (len(a.disp), n_asoc, n_busc))
    P("   Frames analizados ..... %d (gestion: %d, datos: %d)" % (a.total, a.f_mgmt, a.f_data))

    P("\n VEREDICTO DEL AMBIENTE (canal evaluado: %d)" % mi_canal)
    if n_prop:
        v = "LIMPIO" if pct < 15 else ("MODERADO" if pct < 50 else "CONTAMINADO")
        P("   >>> %s (barrido, sin trafico propio)" % v)
        P("   - En el canal %d: %d frames de tu red y %d de redes ajenas (%d%% ajenos)" % (mi_canal, f_prop, f_aj, pct))
        P("   - Si tu red casi no tiene trafico durante el barrido, el % de ajenos sube")
        P("     artificialmente: mira la seccion 5 (medicion con ping).")
    else:
        v = "LIMPIO" if fps_aj < 5 else ("MODERADO" if fps_aj < 30 else "CONTAMINADO")
        P("   >>> %s (barrido)" % v)
        P("   - Tu red de referencia no se detecto; se mide la ocupacion absoluta del canal.")
        P("   - Canal %d: %d frames/s de redes que no son la tuya" % (mi_canal, fps_aj))
        P("   - Umbrales (orientativos): LIMPIO <5, MODERADO <30, CONTAMINADO >=30 frames/s")
    P("   - Redes ajenas en tu mismo canal: %d" % n_mismo)
    P("   - Redes ajenas en canales que se solapan (+-4): %d" % n_solap)

    P("\n [2] TU RED / TU ROUTER (referencia)")
    if not n_prop:
        P("   NO DETECTADA durante la medicion (apagada, fuera de alcance, o sin configurar).")
        P("   El resto del informe sigue siendo valido.")
    for i, r in enumerate(a.redes):
        if not es_propia(r): continue
        av = r.avg()
        P("   SSID ........ %s" % (("(oculta)" if r.oculta else r.ssid) if r.ssid_visto else "(sin baliza)"))
        P("   BSSID ....... %s" % mac_str(r.bssid))
        P("   Canal ....... %d   Seguridad: %s" % (r.canal, SEG_TXT[r.seg] if r.ssid_visto else "?"))
        if r.rssi_n:
            P("   Senal ....... %d dBm promedio (maximo %d) -> %s" % (av, r.rssi_max, prox_txt(av)))
        P("   Frames ...... %d   Dispositivos vistos: %d" % (r.frames, r.n_disp))
        P("   Dispositivos de esta red:")
        P("      %-17s %-6s %-7s %s" % ("MAC", "dBm", "FRAMES", "TIPO"))
        for d in a.disp:
            if d.red != i: continue
            db = str(cdiv(d.rssi_sum, d.rssi_n)) if d.rssi_n else "--"
            P("      %-17s %-6s %-7d %s" % (mac_str(d.mac), db, d.frames,
              "MAC aleatoria (tipico de celular/PC moderno)" if (d.mac[0] & 2) else "MAC fija"))
        P("")

    P(" [3] TABLA DE REDES (de mas cerca a mas lejos)")
    P(" %-3s %-20s %-17s %-3s %-5s %-10s %-7s %-4s %s" %
      ("N", "SSID", "BSSID", "CH", "dBm", "SEGURIDAD", "FRAMES", "DISP", "ESTADO"))
    orden = sorted(a.redes, key=lambda r: -r.avg())          # estable, igual que el firmware
    for k, r in enumerate(orden):
        ch = str(r.canal) if r.canal else "?"
        db = str(r.avg()) if r.rssi_n else "--"
        if es_propia(r): estado = "TU RED"
        elif any(MI_BSSID) and r.bssid[:5] == MI_BSSID[:5]: estado = "posible mismo equipo que tu router"
        elif r.canal and r.canal == mi_canal: estado = "OTRA - MISMO CANAL"
        elif r.canal and abs(r.canal - mi_canal) <= 4: estado = "OTRA - canal solapado"
        else: estado = "OTRA"
        nombre = ("(oculta)" if r.oculta else r.ssid) if r.ssid_visto else "(sin baliza)"
        P(" %-3d %-20.20s %-17s %-3s %-5s %-10s %-7d %-4d %s" %
          (k + 1, nombre, mac_str(r.bssid), ch, db, SEG_TXT[r.seg] if r.ssid_visto else "?",
           r.frames, r.n_disp, estado))

    P("\n [4] OCUPACION POR CANAL")
    P("   %-4s %-12s %-7s %-8s %-9s" % ("CH", "SEG ESCUCHA", "REDES", "FRAMES", "FRAMES/S"))
    mejor, mejor_fps = 0, 0xFFFFFFFF
    for c in range(CANAL_MIN, CANAL_MAX + 1):
        nr = sum(1 for r in a.redes if r.canal == c)
        sc = max(1, a.listen_ms[c] // 1000)
        fps = a.frames_canal[c] // sc
        if c in (1, 6, 11) and fps < mejor_fps:
            mejor_fps, mejor = fps, c
        P("   %-4d %-12d %-7d %-8d %-9d%s" % (c, a.listen_ms[c] // 1000, nr, a.frames_canal[c], fps,
          "  <-- canal evaluado" if c == mi_canal else ""))
    if mejor:
        P("   Canal menos ocupado entre 1, 6 y 11: %d (%d frames/s)" % (mejor, mejor_fps))

    # ---- [5] fase 2
    P("\n [5] PRUEBA CON TRAFICO PROPIO (ping a tu router)")
    if not cfg["ping"]:
        P("   Desactivada (PING_ACTIVO 0).")
    elif p2 is None:
        P("   Sin datos de la fase 2 en esta captura (se corto antes de terminar, o no llego el evento).")
    elif p2["estado"] == 2:
        P("   NO SE PUDO CONECTAR a '%s' en %d s (apagada, fuera de alcance o clave incorrecta)." % (cfg["ssid"], cfg["conn_to"]))
        P("   El resto del informe es valido.")
    elif p2["estado"] == 3:
        P("   Se conecto a '%s' pero no pudo iniciar el ping." % cfg["ssid"])
    else:
        t2 = a.p2_prop + a.p2_aj
        pc = (100 * a.p2_aj // t2) if t2 else 0
        v = "LIMPIO" if pc < 15 else ("MODERADO" if pc < 50 else "CONTAMINADO")
        P("   Conectado a %s (BSSID %s), canal %d" % (cfg["ssid"], mac_str(p2["bssid"]), p2["canal"]))
        P("   IP del sensor %s | ping a %s, %d Hz, durante %d s" %
          (".".join(map(str, p2["ip"])), ".".join(map(str, p2["gw"])), cfg["ping_hz"], cfg["ping_dur"]))
        P("   Frames de tu router ..... %d (%d por segundo)" % (a.p2_prop, a.p2_prop // cfg["ping_dur"]))
        P("   Frames de otras redes ... %d (%d por segundo)" % (a.p2_aj, a.p2_aj // cfg["ping_dur"]))
        if a.p2_rssi_n:
            P("   Senal del router ........ %d dBm promedio" % cdiv(a.p2_rssi_sum, a.p2_rssi_n))
        P("   >>> CON TRAFICO PROPIO: %s (%d%% de frames ajenos)" % (v, pc))

    P("\n [6] COMO LEER ESTE INFORME")
    P("   - 'TU RED' es la referencia configurada en el script (opcional). Todo lo demas")
    P("     es 'OTRA'. 'posible mismo equipo' = BSSID casi igual al tuyo (red de invitados).")
    P("   - El nombre (SSID) sale de las balizas. '(oculta)' = la red no lo anuncia; se")
    P("     revela si algun dispositivo cercano la consulta durante la medicion.")
    P("   - '(sin baliza)' = se vieron frames pero nunca la baliza (senal muy debil): sin nombre.")
    P("   - dBm: cuanto mas cerca de 0, mas fuerte (-30 muy fuerte, -90 casi inaudible).")
    P("     La distancia es orientativa: paredes y muebles la alteran.")
    P("   - Un solo sensor NO da la posicion exacta de un router, solo cercania.")
    P("   - Fase 1: FRAMES es una MUESTRA (el sensor salta de canal). Fase 2: el sensor se")
    P("     conecta a tu router y le hace ping, como en la prueba CSI, y mide solo ese canal.")
    P("   - La captura guarda solo encabezados (no el contenido de los datos). Las MAC estan")
    P("     completas en el archivo .bin: tratalo como privado. Este informe solo lista las MAC")
    P("     de los dispositivos de TU red; de las ajenas muestra cuantas hay.")
    P("   - Redes de 5 GHz no se ven: el ESP32-S3 opera solo en 2.4 GHz.")

    # ---- [7] calidad de la captura (nuevo: ahora hay un cable de por medio)
    P("\n [7] CALIDAD DE LA CAPTURA")
    P("   Frames WiFi recibidos en el archivo ... %d" % a.n_frames_total)
    if stats:
        cb, env, perd = stats
        P("   Frames que oyo la placa ............... %d" % cb)
        P("   Registros perdidos en la placa ........ %d (buffer lleno, cable lento)" % perd)
        if cb and a.n_frames_total > cb:
            P("   Cobertura ............................. no calculable: el archivo trae mas frames (%d) que el" % a.n_frames_total)
            P("                                           ultimo contador de la placa (%d). Ese contador quedo" % cb)
            P("                                           desactualizado (se perdio el aviso final). No es un error de los datos.")
        elif cb:
            P("   Cobertura ............................. %.1f%% de lo que oyo la placa llego a la PC" %
              (100.0 * a.n_frames_total / cb))
        if perd > 0.02 * max(1, cb):
            P("   AVISO: se perdio mas de 2%. Los conteos son una MUESTRA: reduce CAPTURAR_CONTROL,")
            P("          o sube el baud (SER_BAUD) en el firmware y en capturar_wifi.py.")
    if tam_archivo:
        P("   Tamano del archivo .bin ............... %.1f MB" % (tam_archivo / 1e6))
    return L


# ---------------------------------------------------------------- CSV
def exportar_csv(ruta, base):
    out_f = base + "_frames.csv"
    out_e = base + "_eventos.csv"
    with open(out_f, "w", newline="", encoding="utf-8") as fo, open(out_e, "w", newline="", encoding="utf-8") as eo:
        w = csv.writer(fo)
        w.writerow(["t_s", "fase", "pkt", "canal", "rssi", "ruido", "rate", "mcs", "sig_mode", "bw40", "sgi", "stbc",
                    "rx_timestamp_us", "sig_len", "guardados", "tipo", "subtipo", "to_ds", "from_ds", "retry",
                    "addr1", "addr2", "addr3", "seq", "ssid"])
        we = csv.writer(eo)
        we.writerow(["t_s", "evento", "detalle"])
        nombres = {EV_START: "start", EV_CANAL: "canal", EV_FASE: "fase", EV_P2: "ping", EV_STATS: "stats", EV_END: "fin"}
        for t, p in leer_registros(ruta):
            if p[0] == REG_EVENTO:
                we.writerow(["%.6f" % t, nombres.get(p[1], p[1]), p[2:].hex()])
                continue
            fr = decodificar_frame(t, p)
            if fr is None: continue
            d = fr.data
            tipo = sub = to_ds = from_ds = retry = ""
            a1 = a2 = a3 = seq = ssid = ""
            if len(d) >= 2:
                tipo, sub = (d[0] >> 2) & 3, (d[0] >> 4) & 15
                to_ds, from_ds, retry = d[1] & 1, (d[1] >> 1) & 1, (d[1] >> 3) & 1
            if len(d) >= 10: a1 = mac_str(d[4:10])
            if len(d) >= 16: a2 = mac_str(d[10:16])
            if len(d) >= 22: a3 = mac_str(d[16:22])
            if len(d) >= 24 and tipo != 1: seq = (d[22] | (d[23] << 8)) >> 4
            if tipo == 0 and sub in (8, 5) and len(d) >= 38 and d[36] == 0:
                ssid = "".join(chr(c) if 32 <= c < 127 else "?" for c in d[38:38 + min(d[37], 32)])
            elif tipo == 0 and sub == 4 and len(d) >= 26 and d[24] == 0:
                ssid = "".join(chr(c) if 32 <= c < 127 else "?" for c in d[26:26 + min(d[25], 32)])
            w.writerow(["%.6f" % fr.t, fr.fase, TIPOS_PKT.get(fr.pkt, fr.pkt), fr.canal, fr.rssi, fr.noise, fr.rate,
                        fr.mcs, fr.flags & 3, (fr.flags >> 2) & 1, (fr.flags >> 3) & 1, (fr.flags >> 4) & 3,
                        fr.rxts, fr.sig_len, len(d), tipo, sub, to_ds, from_ds, retry, a1, a2, a3, seq, ssid])
    print(f"CSV: {out_f}\n     {out_e}")


# ---------------------------------------------------------------- principal
def main():
    ap = argparse.ArgumentParser(description="Analiza una captura del sniffer WiFi")
    ap.add_argument("archivo")
    ap.add_argument("--csv", action="store_true", help="exportar frames y eventos a CSV")
    ap.add_argument("--sin-txt", action="store_true", help="no guardar el informe en un .txt")
    args = ap.parse_args()

    cfg = dict(dur=180, dwell=400, ch_min=1, ch_max=13, ping=1, ping_hz=50, ping_dur=60, conn_to=20, ssid="?")
    p2 = None
    stats = None
    hay_start = False
    saltos = {"canal_cuenta": [0] * 16}

    # pasada 1: eventos
    for t, p in leer_registros(args.archivo):
        if p[0] != REG_EVENTO or len(p) < 2:
            continue
        ev = p[1]
        if ev == EV_START and not hay_start and len(p) >= 16:
            _v, dur, dwell, c0, c1, pa, hz, pd, ct, _cc, sl = struct.unpack_from("<BHHBBBBHBBB", p, 2)
            cfg.update(dur=dur, dwell=dwell, ch_min=c0, ch_max=c1, ping=pa, ping_hz=hz, ping_dur=pd, conn_to=ct,
                       ssid=p[16:16 + sl].decode("utf-8", "replace"))
            hay_start = True
        elif ev == EV_CANAL and len(p) >= 3 and p[2] < 16:
            saltos["canal_cuenta"][p[2]] += 1
        elif ev == EV_P2 and len(p) >= 18:
            p2 = dict(estado=p[2], canal=p[3], bssid=bytes(p[4:10]), ip=tuple(p[10:14]), gw=tuple(p[14:18]))
        elif ev == EV_STATS and len(p) >= 16:
            stats = struct.unpack_from("<III", p, 2)        # acumulados: nos quedamos con el ultimo
    if not hay_start:
        print("Aviso: la captura no trae la configuracion de la placa; se usan valores por defecto.", file=sys.stderr)

    a = Analisis()
    for c in range(16):
        a.listen_ms[c] = saltos["canal_cuenta"][c] * cfg["dwell"]
    if p2 and p2["estado"] in (1, 3):
        a.p2_bssid = p2["bssid"]

    # pasada 2: frames
    for t, p in leer_registros(args.archivo):
        if p[0] == REG_FRAME:
            fr = decodificar_frame(t, p)
            if fr is not None:
                a.frame(fr)

    informe = generar_informe(a, cfg, p2, stats, os.path.getsize(args.archivo))
    texto = "\n".join(informe) + "\n"
    print(texto)
    base = os.path.splitext(args.archivo)[0]
    if not args.sin_txt:
        ruta = base + "_informe.txt"
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(texto)
        print(f"INFORME GUARDADO EN: {os.path.abspath(ruta)}")
    if args.csv:
        exportar_csv(args.archivo, base)


if __name__ == "__main__":
    main()