#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# write_mifare_try_keyA_keyB.py
# Intenta autenticar con Key A; si falla, intenta Key B.
# Escribe "hola mundo" (16 bytes) en el bloque físico 4 (sector 1, primer bloque de datos)
# Requisitos: adafruit-blinka, adafruit-circuitpython-pn532

import time
import board
import busio
from digitalio import DigitalInOut
from adafruit_pn532.i2c import PN532_I2C

# ---- CONFIG ----
BLOCK_TO_WRITE = 4  # bloque físico (sector 1 -> bloque 4)
# Key A y Key B extraídas de tu volcado
KEY_A_HEX = "D3F7D3F7D3F7"   # 6 bytes
KEY_B_HEX = "FFFFFFFFFFFF"   # 6 bytes (ejemplo del dump)
KEY_A = bytes.fromhex(KEY_A_HEX)
KEY_B = bytes.fromhex(KEY_B_HEX)

TEXT = "hola mundo"
req_pin = None  # si tu placa PN532 requiere una línea REQ/IRQ, configúrala aquí: DigitalInOut(board.D12)
# -----------------

def text_to_16bytes(s: str) -> bytes:
    b = s.encode('utf-8')
    if len(b) > 16:
        return b[:16]
    return b + b'\x00' * (16 - len(b))

def try_authenticate(pn532, block, key, key_label):
    """
    Intenta autenticar un bloque usando varias firmas que la librería puede requerir.
    Devuelve True si se autentica correctamente.
    """
    # Algunos bindings aceptan key_type 'A'/'B', otros esperan 0x60/0x61
    attempts = []
    # intento con string 'A'/'B'
    if key_label == 'A':
        attempts.append('A')
        attempts.append(0x60)
    else:
        attempts.append('B')
        attempts.append(0x61)

    for kt in attempts:
        try:
            auth = pn532.mifare_classic_authenticate_block(block, key, key_type=kt)
            if auth:
                print(f"Autenticación exitosa con Key {key_label} usando key_type={kt}")
                return True
        except TypeError:
            # Si la firma del método es diferente, probamos sin nombre de parámetro posicional
            try:
                auth = pn532.mifare_classic_authenticate_block(block, key, kt)
                if auth:
                    print(f"Autenticación exitosa con Key {key_label} usando key_type(pos)={kt}")
                    return True
            except Exception:
                pass
        except Exception as e:
            # No detenerse por excepción puntual; seguir intentando otras firmas
            # imprimimos la excepción para diagnóstico
            print(f"Intento con key_type={kt} produjo excepción: {e}")
    return False

def main():
    # Inicializar I2C y PN532
    i2c = busio.I2C(board.SCL, board.SDA)
    pn532 = PN532_I2C(i2c, debug=False, reset=None, req=req_pin)

    try:
        ic, ver, rev, support = pn532.firmware_version
        print(f"PN532 firmware version: {ver}.{rev}, soporta: {support}")
    except Exception as e:
        print("No se pudo leer versión del PN532. Revisa conexiones/jumpers I2C. Excepción:", e)
        return

    pn532.SAM_configuration()
    print("PN532 listo. Acerca la tarjeta MIFARE Classic...")

    while True:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid is None:
            print(".", end="", flush=True)
            time.sleep(0.5)
            continue

        print("\nTarjeta detectada. UID:", [hex(i) for i in uid])

        # Intento con Key A
        print(f"Intentando autenticar bloque {BLOCK_TO_WRITE} con Key A ({KEY_A_HEX})...")
        ok = try_authenticate(pn532, BLOCK_TO_WRITE, KEY_A, 'A')

        # Si falla Key A, intentar con Key B automáticamente
        if not ok:
            print(f"Key A falló. Intentando con Key B ({KEY_B_HEX})...")
            ok = try_authenticate(pn532, BLOCK_TO_WRITE, KEY_B, 'B')

            if not ok:
                print("Autenticación fallida con Key A y Key B. No se puede escribir.")
                # seguir esperando otra tarjeta o repetir (no escribimos)
                continue
            else:
                key_used = KEY_B
                key_used_hex = KEY_B_HEX
        else:
            key_used = KEY_A
            key_used_hex = KEY_A_HEX

        print(f"Autenticación OK. Key usada: {key_used_hex}")

        # Preparar datos y escribir
        data = text_to_16bytes(TEXT)
        print("Datos a escribir (hex):", data.hex())

        try:
            pn532.mifare_classic_write_block(BLOCK_TO_WRITE, data)
            print(f"Escritura completada en bloque {BLOCK_TO_WRITE}.")
        except Exception as e:
            print("Error al escribir el bloque:", e)
            continue

        # Leer de vuelta para verificar
        try:
            read_back = pn532.mifare_classic_read_block(BLOCK_TO_WRITE)
            if read_back is None:
                print("Lectura fallida después de escribir.")
            else:
                read_bytes = bytes(read_back)
                print("Lectura (hex):", read_bytes.hex())
                print("Lectura (texto):", read_bytes.rstrip(b'\x00').decode('utf-8', errors='replace'))
        except Exception as e:
            print("Error leyendo el bloque:", e)

        print("Operación finalizada. Salida del script.")
        break

if __name__ == "__main__":
    main()
