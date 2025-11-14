import re
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def fnv1a_32_hash(data_string):
    hash_value = 2166136261
    fnv_prime = 16777619
    for char in data_string.encode('utf-8'):
        hash_value = (hash_value * fnv_prime) ^ char
    return hash_value & 0xFFFFFFFF

def rle_compress(data):
    if not data:
        return ""
    encoded_data = ""
    i = 0
    while i < len(data):
        char = data[i]
        count = 1
        i += 1
        while i < len(data) and data[i] == char:
            count += 1
            i += 1
        encoded_data += str(count) + char
    return encoded_data

def rle_decompress(encoded_data):
    decoded_data = ""
    matches = re.findall(r'(\d+)(.)', encoded_data)
    for count, char in matches:
        decoded_data += char * int(count)
    return decoded_data

def generar_claves_rsa():
    key_pair = RSA.generate(2048)
    clave_privada = key_pair
    clave_publica = key_pair.publickey()
    return clave_privada, clave_publica

def firmar_hash(hash_fnv, clave_privada):
    datos_a_firmar = str(hash_fnv).encode('utf-8')
    hash_rsa = SHA256.new(datos_a_firmar)
    signer = pkcs1_15.new(clave_privada)
    firma = signer.sign(hash_rsa)
    return base64.b64encode(firma)

def verificar_firma(hash_fnv_calculado, firma_b64, clave_publica):
    datos_a_verificar = str(hash_fnv_calculado).encode('utf-8')
    hash_rsa = SHA256.new(datos_a_verificar)
    try:
        firma_bytes = base64.b64decode(firma_b64)
    except Exception:
        return False
    verifier = pkcs1_15.new(clave_publica)
    try:
        verifier.verify(hash_rsa, firma_bytes)
        return True
    except (ValueError, TypeError):
        return False

def main():
    mensaje_original = None
    hash_fnv = None
    mensaje_comprimido = None
    firma_digital = None
    paquete_enviado = {}
    resultado_verificacion = None

    print("Generando claves RSA (2048 bits). Espere.")
    clave_privada, clave_publica = generar_claves_rsa()
    print("Claves generadas. Privada guardada. Pública lista.")

    while True:
        print("\n--- MENÚ DE MENSAJERÍA SEGURA ---")
        print("1. Ingresar mensaje")
        print("2. Calcular hash FNV-1")
        print("3. Comprimir mensaje (RLE)")
        print("4. Firmar el hash con la clave privada RSA")
        print("5. Simular envío (mensaje comprimido + firma + clave pública)")
        print("6. Descomprimir y verificar firma (con clave pública)")
        print("7. Mostrar si el mensaje es auténtico o alterado")
        print("8. Salir")
        
        opcion = input("Seleccione una opción: ")

        if opcion == '1':
            mensaje_original = input("Ingrese el mensaje de texto: ")
            hash_fnv = None
            mensaje_comprimido = None
            firma_digital = None
            paquete_enviado = {}
            resultado_verificacion = None
            print(f"Mensaje guardado: '{mensaje_original}'")

        elif opcion == '2':
            if mensaje_original is None:
                print("Error: Ingrese mensaje (Opción 1).")
                continue
            hash_fnv = fnv1a_32_hash(mensaje_original)
            print(f"Hash FNV-1a (32-bit): {hash_fnv}")

        elif opcion == '3':
            if mensaje_original is None:
                print("Error: Ingrese mensaje (Opción 1).")
                continue
            
            mensaje_comprimido = rle_compress(mensaje_original)
            tam_antes = len(mensaje_original.encode('utf-8'))
            tam_despues = len(mensaje_comprimido.encode('utf-8'))
            
            print("Mensaje comprimido con RLE.")
            print(f"   Tamaño antes: {tam_antes} bytes")
            print(f"   Tamaño después: {tam_despues} bytes")
            print(f"   Comprimido: {mensaje_comprimido}")

        elif opcion == '4':
            if hash_fnv is None:
                print("Error: Calcule hash (Opción 2).")
                continue
            
            firma_digital = firmar_hash(hash_fnv, clave_privada)
            print("Hash firmado con Clave Privada.")
            print(f"\n   Firma Digital (Base64): {firma_digital.decode('utf-8')}")
            print("\n   --- CLAVE PÚBLICA ---")
            print(clave_publica.export_key('PEM').decode('utf-8'))
            print("   --- CLAVE PRIVADA (Secreta) ---")
            print(clave_privada.export_key('PEM').decode('utf-8'))

        elif opcion == '5':
            if mensaje_comprimido is None or firma_digital is None:
                print("Error: Comprima (Opción 3) y Firme (Opción 4).")
                continue
            
            paquete_enviado = {
                'msg_comprimido': mensaje_comprimido,
                'firma': firma_digital,
                'clave_pub': clave_publica
            }
            print("Envío simulado. Paquete en memoria.")
            print("   Contenido: [Mensaje Comprimido] + [Firma] + [Clave Pública]")

        elif opcion == '6':
            if not paquete_enviado:
                print("Error: Envíe paquete (Opción 5).")
                continue
            
            print("\n--- Recepción y Verificación ---")
            
            msg_com_rec = paquete_enviado['msg_comprimido']
            firma_rec = paquete_enviado['firma']
            cpub_rec = paquete_enviado['clave_pub']

            msg_descom = rle_decompress(msg_com_rec)
            print(f"1. Mensaje descomprimido: '{msg_descom}'")

            hash_calc_receptor = fnv1a_32_hash(msg_descom)
            print(f"2. Hash FNV-1 (receptor): {hash_calc_receptor}")

            print("3. Verificando firma con clave pública.")
            es_valida = verificar_firma(hash_calc_receptor, firma_rec, cpub_rec)
            
            resultado_verificacion = es_valida 
            
            if es_valida:
                print("Éxito. Firma válida.")
            else:
                print("FALLO. Firma NO válida.")

        elif opcion == '7':
            if resultado_verificacion is None:
                print("Estado: No verificado (Opción 6).")
            elif resultado_verificacion:
                print("RESULTADO: Mensaje auténtico y no modificado.")
            else:
                print("RESULTADO: Mensaje alterado o firma no válida.")

        elif opcion == '8':
            print("Saliendo.")
            break
        
        else:
            print("Opción no válida. Intente de nuevo.")

if __name__ == "__main__":
    main()