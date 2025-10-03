import board
import busio
from digitalio import DigitalInOut
from adafruit_pn532.i2c import PN532_I2C

# Inicializar bus I2C
i2c = busio.I2C(board.SCL, board.SDA)

# Pines para reset y request (wakeup) en Raspberry Pi para evitar problemas de I2C
reset_pin = DigitalInOut(board.D25)  # GPIO 25 (pin 22)
req_pin = DigitalInOut(board.D18)    # GPIO 18 (pin 12)

# Inicializar PN532 en modo I2C
pn532 = PN532_I2C(i2c, debug=False, reset=reset_pin, req=req_pin)

# Verificar firmware del PN532
ic, ver, rev, support = pn532.firmware_version
print('Encontrado PN532 con versión de firmware: {0}.{1}'.format(ver, rev))

# Configurar para tarjetas MiFare
pn532.SAM_configuration()

print("Esperando tarjeta MIFARE Classic...")

while True:
    # Detectar tarjeta pasiva (timeout de 0.5 segundos)
    uid = pn532.read_passive_target(timeout=0.5)
    if uid is None:
        continue
    
    print('Tarjeta detectada con UID:', [hex(i) for i in uid])
    
    # Clave A por defecto para MIFARE Classic
    key = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    
    # Autenticar bloque 4 con clave A (True para clave A, False para B)
    if pn532.mifare_classic_authenticate_block(uid, 4, key, True):
        print("Autenticación exitosa para bloque 4.")
        
        # Leer datos del bloque 4
        data = pn532.mifare_classic_read_block(4)
        if data:
            print("Contenido del bloque 4:", [hex(i) for i in data])
        else:
            print("Error al leer bloque 4.")
    else:
        print("Error en autenticación del bloque 4. ¿Clave correcta?")
    
    # Esperar antes de la siguiente lectura (ajusta si necesitas loop continuo)
    input("Presiona Enter para leer otra tarjeta...")