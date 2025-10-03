#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# read_mifare_dump.py
# Lee una tarjeta MIFARE Classic 1K usando PN532 por I2C.
# Requisitos: adafruit-blinka, adafruit-circuitpython-pn532

import time
import board
import busio
from adafruit_pn532.i2c import PN532_I2C

# ----------------- CONFIG -----------------
# Lista de claves (hex 12 chars, 6 bytes). Añade aquí las claves que quieras probar.
KEYS_HEX = [
    "D3F7D3F7D3F7",  # la que encontraste en tu volcado (sectores 1-15)
    "A0A1A2A3A4A5",  # la de sector 0 en tu volcado
    "FFFFFFFFFFFF",  # key por defecto muy común
    "000000000000",  # otra clave común
    # agrega más si las conoces...
]

# Si tu PN532 necesita pin IRQ/REQ ponlo aquí (p. ej. board.D12), o deja None
REQ_PIN = None

# MIFARE Classic 1K tiene 16 sectores (0..15), 4 bloques por sector
SECTORS = range(0, 16)
BLOCKS_PER_SECTOR = 4
# ------------------------------------------

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def printable(b: bytes) -> str:
    # convierte a texto reemplazando bytes no imprimibles por '.'
    return ''.join((chr(c) if 32 <= c <= 126 else '.') for c in b)

def try_authenticate(pn532, block_number, key_bytes, key_label):
    """
    Intenta autenticar block_number con la clave key_bytes.
    Prueba variantes de key_type que usan diferentes bindings.
    Devuelve True si la autenticación fue exitosa.
    """
    # order: probar como Key A (0x60/'A') o Key B (0x61/'B') según key_label
    key_types = []
    if key_label == 'A':
        key_types = ['A', 0x60]
    else:
        key_types = ['B', 0x61]

    for kt in key_types:
        try:
            auth = pn532.mifare_classic_authenticate_block(block_number, key_bytes, key_type=kt)
            if auth:
                return True
        except TypeError:
            # algunos bindings usan parametros posicionales
            try:
                auth = pn532.mifare_classic_authenticate_block(block_number, key_bytes, kt)
                if auth:
                    return True
            except Exception:
                pass
        except Exception:
            # ignorar otras excepciones y seguir probando
            pass
    return False

def main():
    print("Inicializando I2C y PN532...")
    i2c = busio.I2C(board.SCL, board.SDA)
    pn532 = PN532_I2C(i2c, debug=False, reset=None, req=REQ_PIN)

    try:
        ic, ver, rev, support = pn532.firmware_version
        print(f"PN532 firmware: {ver}.{rev}  soporte: {support}")
    except Exception as e:
        print("No se pudo leer firmware del PN532. Revisa cables/jumpers I2C. Excepción:", e)
        return

    pn532.SAM_configuration()
    print("PN532 listo. Acerca la tarjeta MIFARE Classic...")

    # Preconvertir claves a bytes para eficiencia
    keys = [(k, hex_to_bytes(k)) for k in KEYS_HEX]

    while True:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid is None:
            print(".", end="", flush=True)
            time.sleep(0.4)
            continue

        print("\n\n=== Tarjeta detectada. UID:", [hex(x) for x in uid], "===\n")
        # Recorremos sectores y bloques
        for sector in SECTORS:
            sector_base_block = sector * BLOCKS_PER_SECTOR
            print(f"-- Sector {sector} (bloques {sector_base_block}..{sector_base_block + BLOCKS_PER_SECTOR -1}) --")
            for b in range(BLOCKS_PER_SECTOR):
                block_num = sector_base_block + b
                read_success = False
                used_key = None
                used_key_type = None

                # probar cada key: primero como Key A, luego como Key B
                for (khex, kbytes) in keys:
                    # intentar como Key A
                    if try_authenticate(pn532, block_num, kbytes, 'A'):
                        used_key = khex
                        used_key_type = 'A'
                        try:
                            data = pn532.mifare_classic_read_block(block_num)
                            if data is None:
                                print(f"  Block {block_num:02d}: auth A with {khex} -> read returned None")
                            else:
                                read_success = True
                                data_bytes = bytes(data)
                                print(f"  Block {block_num:02d}: [Key A {khex}] hex: {data_bytes.hex()} | ascii: {printable(data_bytes)}")
                        except Exception as e:
                            print(f"  Block {block_num:02d}: [Key A {khex}] auth ok but read error: {e}")
                        break  # no probar otras keys si auth A funcionó

                    # intentar como Key B
                    if try_authenticate(pn532, block_num, kbytes, 'B'):
                        used_key = khex
                        used_key_type = 'B'
                        try:
                            data = pn532.mifare_classic_read_block(block_num)
                            if data is None:
                                print(f"  Block {block_num:02d}: auth B with {khex} -> read returned None")
                            else:
                                read_success = True
                                data_bytes = bytes(data)
                                print(f"  Block {block_num:02d}: [Key B {khex}] hex: {data_bytes.hex()} | ascii: {printable(data_bytes)}")
                        except Exception as e:
                            print(f"  Block {block_num:02d}: [Key B {khex}] auth ok but read error: {e}")
                        break

                if not read_success:
                    # Si no se leyó, indicar por qué (no autenticado / protegido)
                    print(f"  Block {block_num:02d}: No autenticado con las claves probadas.")
            print("")  # línea en blanco entre sectores

        print("Lectura completa. Sal del script con CTRL+C o acerca otra tarjeta para repetir.")
        # opcional: salir tras una tarjeta leída; si prefieres loop continuo, quita el break
        break

if __name__ == "__main__":
    main()
