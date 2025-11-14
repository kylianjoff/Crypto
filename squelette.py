from Crypto.Cipher import AES
import paho.mqtt.client as mqtt
import time
import random

BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Informations de connexion MQTT

IP = "172.16.32.7"
PORT = 10801
GROUPE = "GROUPE_BOURGEOIS_JULIA"
SECRET = "........"

MODE_MQTT = "LECT" # "LECT" pour écoute seule, "ECR" pour écriture seule

LOG_MQTT_ECOUTE = False # Paramètre pour activer ou désactiver l'authentification MQTT pour l'écoute
MQTT_LOGIN_ECOUTE = "" # user_x_y
MQTT_PASSWORD_ECOUTE = "" #user_x_y

LOG_MQTT_ECRITURE = False # Paramètre pour activer ou désactiver l'authentification MQTT pour l'écriture
MQTT_LOGIN_ECRITURE = "" # user_x_y
MQTT_PASSWORD_ECRITURE = "" # user_x_y

# Topics MQTT

TOPIC_ECOUTE = "ISIMA/SECRET_ZZZ/CHALLENGE_2/DEFI_Y/GROUPE_BOURGEOIS_JULIA/LEDS/LED1"
TOPIC_ECRITURE = "ISIMA/SECRET_ZZZ/CHALLENGE_2/DEFI_Y/GROUPE_BOURGEOIS_JULIA/LEDS/LED2"

# Fonctions d'encodage / décodage

# ----- Xor -----

def EncodeXor(tabMessage, tabKey):
    """
    Chiffrement OU exclusif
    tabMessage contient le message sous forme de tableau d'octets
    tabKey contient la clef sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    key_len = len(tabKey)
    result = bytearray()
    for i, b in enumerate(tabMessage):
        result.append(b ^ tabKey[i % key_len])
    return bytes(result)

def DecodeXor(tabMessage, tabKey):
    """
    Chiffrement OU exclusif
    tabMessage contient le message sous forme de tableau d'octets
    tabKey contient la clef sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    return EncodeXor(tabMessage, tabKey)

# ----- Base64 -----

def EncodeBase64(tabMessage):
    """
    Encode en Base64 le paramÃ¨tre tabMessage (tableau d'octets)
    Retourne un tableau d'octets
    """
    result = bytearray()
    padding = 0
    # Traiter les octets 3 par 3
    for i in range(0, len(tabMessage), 3):
        chunk = tabMessage[i:i+3]
        if len(chunk) < 3:
            padding = 3 - len(chunk)
            chunk += b'\x00' * padding
        # Convertir les 3 octets en 24 bits
        bits = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]
        # Extraire 4 groupes de 6 bits
        for j in range(18, -1, -6):
            index = (bits >> j) & 0x3F
            result.append(BASE64_ALPHABET[index])
    # Remplacer par '=' selon le padding
    if padding:
        result = result[:-padding] + b'=' * padding
    return bytes(result)

def DecodeBase64(strMessage):
    if isinstance(strMessage, str):
        strMessage = strMessage.encode('ascii')  # convertir en bytes
    decoded_bytes = bytearray()
    # Traiter les caractÃ¨res 4 par 4
    for i in range(0, len(strMessage), 4):
        chunk = strMessage[i:i+4]
        # Compter le padding dans ce chunk
        pad = chunk.count(b'=')
        chunk = chunk.rstrip(b'=')
        # Convertir chaque octet en 6 bits
        bits = 0
        for c in chunk:
            bits = (bits << 6) + BASE64_ALPHABET.index(c)
        # Ajouter des zÃ©ros si padding pour complÃ©ter 24 bits
        bits <<= 6 * pad
        # Extraire les octets rÃ©els
        num_bytes = len(chunk) - 1 + pad
        for j in range(16, 16 - 8 * (3 - pad), -8):
            decoded_bytes.append((bits >> j) & 0xFF)
    return bytes(decoded_bytes)

# ----- AES ECB -----

def EncodeAES_ECB(strMessage, tabKey):
    """
    Chiffrement AES-128 ECB
    strMessage : str ou bytes
    tabKey : liste ou bytes de 16 octets
    Retourne : bytes
    """
    if len(tabKey) != 16:
        raise ValueError("La clÃ© doit contenir exactement 16 octets")
    
    key_bytes = bytes(tabKey)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    
    # Si strMessage est une chaÃ®ne, l'encoder
    if isinstance(strMessage, str):
        message_bytes = strMessage.encode('utf-8')
    else:
        message_bytes = bytes(strMessage)  # accepte dÃ©jÃ  bytes ou bytearray
    
    # Padding pour complÃ©ter les blocs de 16 octets
    if len(message_bytes) % 16 != 0:
        padding_len = 16 - (len(message_bytes) % 16)
        message_bytes += b' ' * padding_len
    
    return cipher.encrypt(message_bytes)

def DecodeAES_ECB(strMessage, tabKey):
    """
    DÃ©chiffrement AES-ECB.
    - strMessage : tableau d'octets chiffrÃ©
    - tabKey : tableau de 16 octets (clÃ© AES-128)
    Retourne : tableau d'octets (plaintext)
    Les caractÃ¨res espaces ajoutÃ©s pour le padding seront supprimÃ©s Ã  la fin.
    VÃ©rifie que la longueur est un multiple de 16 octets avant dÃ©chiffrement.
    """

    if len(tabKey) != 16:
        raise ValueError("La clÃ© doit contenir exactement 16 octets")

    key_bytes = bytes(tabKey)

    # VÃ©rifier l'alignement sur bloc AES
    if len(strMessage) % AES.block_size != 0:
        raise ValueError(f"Le ciphertext doit avoir une longueur multiple de {AES.block_size} (len={len(strMessage)})")

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(strMessage)

    # Retirer les espaces ajoutÃ©s pour le padding (compatible avec ton EncodeAES_ECB)
    return decrypted_bytes.rstrip(b' ')

# Fonctions de piratage

# ----- Force Brute sur Xor -----

def ForceBruteXor4(tabMessage):
    indice1=0
    indice2=0
    indice3=0
    indice4=0
    tab1=[0,1,2,3,4,5,6,7,8,9]
    tab2=[0,1,2,3,4,5,6,7,8,9]
    tab3=[0,1,2,3,4,5,6,7,8,9]
    tab4=[0,1,2,3,4,5,6,7,8,9]

    while(indice1<10):
        indice2=0
        while(indice2<10):
            indice3=0
            while(indice3<10):
                indice4=0
                while(indice4<10):
                    cle=str(indice1)+str(indice2)+str(indice3)+str(indice4)
                    l=[EncodeXor(tabMessage,cle.encode())[i::4] for i in range(4)]
                    
                    if (not(all(EstImprimable(chr(b)) for b in l[0]))):
                        
                        tab1[indice1]=-1

                    if (not(all(EstImprimable(chr(b)) for b in l[1]))):
                        tab2[indice2]=-1

                    if (not(all(EstImprimable(chr(b)) for b in l[2]))):
                        tab3[indice3]=-1

                    if (not(all(EstImprimable(chr(b)) for b in l[3]))):
                        tab4[indice4]=-1
                    indice4+=1
                indice3+=1
            indice2+=1
        indice1+=1
            
            
    return([tab1,tab2,tab3,tab4])
            
def ForceBruteXorSetKeySize(tabMessage,keysize):
    '''
    Fonction prenant en argument le message et la taille de la clÃ© et qui brute force la clÃ©
    Retourne une liste de liste des character possible pour chaque position
    '''
    indice_char=0
    s="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    tab=[j for j in range(len(s))]*keysize

    
    while(indice_char<len(s)):
        cle=s[indice_char]*keysize
        l=[EncodeXor(tabMessage,cle.encode())[j::keysize] for j in range(keysize)]
        
        for indice_cle in range(keysize):
            if (not(all(EstImprimable(chr(b)) for b in l[indice_cle]))):
                tab[indice_char+indice_cle*len(s)]=-1
                
        indice_char+=1
    out=[[s[tab[i+k*len(s)]]for i in range(len(s))if tab[i+k*len(s)]!=-1]for k in range(keysize)]
    return(out)

def ForceBruteXor(tabMessage,upperkeysize):
    '''
    Bruteforce la clÃ© d'un message tabMessage cryptÃ© en Xor avec une taille de clÃ© allant jusqu'a upperkeysize
    Retourne une liste contenant la clÃ© trouvÃ©e
    10 seconde pour upperkeysize=15
    36 seconde pour upperkeysize=30
    1:40 pour upperkeysize=52
    '''
    res=[]
    for keysize in range(1,upperkeysize+1):
        test =ForceBruteXorSetKeySize(tabMessage,keysize)
        if (all([len(test[j])==1 for j in range (keysize)])):
            res.append(''.join(test[j][0]for j in range (keysize)))
            break
        print(keysize)
    return(res)

# ----- Dictionnaire sur AES -----

def dictionnaire(tabMessage,path):
    f=open(path,'r')
    keys=f.read().splitlines()
    res=[]
    for key in keys:
        bkey=key.encode()
        keyfilled=bkey
        if (len(keyfilled)>16):
            keyfilled=bkey[0:16]
        if (len(bkey)<16):
            keyfilled=bkey+bytearray(16-len(bkey))
        test =DecodeAES_ECB(tabMessage,keyfilled)
        if (all([EstImprimable(chr(b)) for b in test])):
            res.append(key)
            break
        print(key)
    return(res)

# Autres fonctions utilitaires

def Contient(aiguille, chaine):
    """
    RÃ©sultat True si le paramÃ¨tre chaine contient aiguille
    """
    return aiguille in chaine

def EstImprimable(caractere):
    """
    Liste des caractÃ¨res imprimables :
    0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    """
    c_imprimables = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "
    return Contient(caractere,c_imprimables)

def Remplace(chaine, avant, apres):
    """
    Remplace toutes les occurrences de 'avant' par 'apres' dans 'chaine'.
    """
    return chaine.replace(avant, apres)

def Extraire(chaine, separation, n):
    """
    Retourne le niÃ¨me champ de 'chaine', sÃ©parÃ© par 'separation'.
    Si le champ est numÃ©rique, les zÃ©ros initiaux sont retirÃ©s et on retourne un int.
    Indexation : n = 0 pour le premier champ.
    """
    champ = ""
    compteur = 0

    for c in chaine:
        if c == separation:
            if compteur == n:
                break
            champ = ""
            compteur += 1
        else:
            champ += c

    # VÃ©rifie si c'Ã©tait le dernier champ
    if compteur != n:
        return None

    # Si le champ est composÃ© uniquement de chiffres, le convertir en int
    if champ.isdigit():
        return int(champ)
    return champ

def Format(n):
    """
    Retourne une chaÃ®ne de 4 caractÃ¨res pour tout nombre entier de 0 Ã  9999,
    avec des zÃ©ros initiaux si nÃ©cessaire.
    """
    if not (0 <= n <= 9999):
        raise ValueError("Le nombre doit Ãªtre compris entre 0 et 9999")
    return f"{n:04d}"

def toTab(strMessage):
    """
    Encode une chaine en tableau d'octets. l'encodage utilisÃ© est "utf-8
    """
    return strMessage.encode('utf-8')

def toStr(strMessage):
    """
    Decode un tableau d'octets en chaine utf-8
    """
    return strMessage.decode('utf-8')

def Indice(tableau, element):
    """
    Retourne l'indice de l'Ã©lÃ©ment du tableau
    """
    for i in range(len(tableau)):
        if tableau[i] == element:
            return i
    return -1

# Compteur et salage

def AjoutCompteur(tabMessage, compteur=1):
    """
    Ajout d'un compteur au message sur 4 caractÃ¨res
    tabMessage contient le message sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    compteur_byte = Format(compteur)
    message_compte = tabMessage + compteur_byte
    return message_compte

def Salage(tabMessage):
    """
    Ajout du salage au message sur 8 caractÃ¨res
    tabMessage contient le message sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    sel = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    messageSalted = tabMessage + sel.encode()
    return messageSalteds

# Callbacks MQTT

def on_connect(client, userdata, flags, rc, properties):
    print("--Connected with result code => "+mqtt.connack_string(rc))
    client.connected=(rc==0)

def on_subscribe(client, userdata, mid, granted_qos):
    print("--Subscribed: mid: " + str(mid) + " QoS" + str(granted_qos))

def on_message(client, userdata, msg):
    print("--Received message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos))
    if "LED2_HACKED" in msg.topic and GROUPE in msg.topic:
        client.hacked=True
        print("\nWell done !")

    #Evite de travailler sur ces propres messages
    if not ("GROUPE_XX" in msg.topic):
        return

    #Construction du nouveau payload ICI

    if False:#si construction payload OK :
        topic=msg.topic
        topic=topic.replace("GROUPE_XX",GROUPE)
        topic=topic.replace("LED1","LED2")
        client.publish(topic,newpayload)

def on_publish(client, userdata, mid):
    print("--on_publish callback --mid: " + str(mid) )

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="GROUPE")
client.connected=False
client.hacked=False
client.on_connect = on_connect
client.on_subscribe = on_subscribe
client.on_message = on_message
client.on_publish = on_publish

try:
    if(LOG_MQTT):
        client.username_pw_set(username=MQTT_LOGIN, password=MQTT_PASSWORD)
    client.connect(IP, PORT)
    client.subscribe(TOPIC_ECOUTE, qos=0)
    client.loop_start()

    while not client.hacked:
        time.sleep(0.5)
        print(".",end='')


except ConnectionRefusedError:
    print("Connection Failed Bad IP / PORT")

except KeyboardInterrupt:
    print("\nBreak signal")
    pass

client.loop_stop()
client.unsubscribe("#")
client.disconnect()
print("Finished.")