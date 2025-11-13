'''from Crypto.Cipher import AES'''
import random
import string

BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def AjoutCompteur(tabMessage, compteur=1):
    """
    Ajout d'un compteur au message sur 4 caractères
    tabMessage contient le message sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    compteur_byte = Format(compteur)
    message_compte = tabMessage + compteur_byte
    return message_compte

def Salage(tabMessage):
    """
    Ajout du salage au message sur 8 caractères
    tabMessage contient le message sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    sel = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    messageSalted = tabMessage + sel.encode()
    return messageSalted

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

def Indice(tableau, element):
    """
    Retourne l'indice de l'élément du tableau
    """
    for i in range(len(tableau)):
        if tableau[i] == element:
            return i
    return -1

def EncodeBase64(tabMessage):
    """
    Encode en Base64 le paramètre tabMessage (tableau d'octets)
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
    # Traiter les caractères 4 par 4
    for i in range(0, len(strMessage), 4):
        chunk = strMessage[i:i+4]
        # Compter le padding dans ce chunk
        pad = chunk.count(b'=')
        chunk = chunk.rstrip(b'=')
        # Convertir chaque octet en 6 bits
        bits = 0
        for c in chunk:
            bits = (bits << 6) + BASE64_ALPHABET.index(c)
        # Ajouter des zéros si padding pour compléter 24 bits
        bits <<= 6 * pad
        # Extraire les octets réels
        num_bytes = len(chunk) - 1 + pad
        for j in range(16, 16 - 8 * (3 - pad), -8):
            decoded_bytes.append((bits >> j) & 0xFF)
    return bytes(decoded_bytes)

def EncodeAES_ECB(strMessage, tabKey):
    """
    Chiffrement AES-128 ECB
    strMessage : str ou bytes
    tabKey : liste ou bytes de 16 octets
    Retourne : bytes
    """
    if len(tabKey) != 16:
        raise ValueError("La clé doit contenir exactement 16 octets")
    
    key_bytes = bytes(tabKey)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    
    # Si strMessage est une chaîne, l'encoder
    if isinstance(strMessage, str):
        message_bytes = strMessage.encode('utf-8')
    else:
        message_bytes = bytes(strMessage)  # accepte déjà bytes ou bytearray
    
    # Padding pour compléter les blocs de 16 octets
    if len(message_bytes) % 16 != 0:
        padding_len = 16 - (len(message_bytes) % 16)
        message_bytes += b' ' * padding_len
    
    return cipher.encrypt(message_bytes)

def DecodeAES_ECB(strMessage, tabKey):
    """
    Déchiffrement AES-ECB.
    - strMessage : tableau d'octets chiffré
    - tabKey : tableau de 16 octets (clé AES-128)
    Retourne : tableau d'octets (plaintext)
    Les caractères espaces ajoutés pour le padding seront supprimés à la fin.
    Vérifie que la longueur est un multiple de 16 octets avant déchiffrement.
    """

    if len(tabKey) != 16:
        raise ValueError("La clé doit contenir exactement 16 octets")

    key_bytes = bytes(tabKey)

    # Vérifier l'alignement sur bloc AES
    if len(strMessage) % AES.block_size != 0:
        raise ValueError(f"Le ciphertext doit avoir une longueur multiple de {AES.block_size} (len={len(strMessage)})")

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(strMessage)

    # Retirer les espaces ajoutés pour le padding (compatible avec ton EncodeAES_ECB)
    return decrypted_bytes.rstrip(b' ')

def Contient(aiguille, chaine):
    """
    Résultat True si le paramètre chaine contient aiguille
    """
    return aiguille in chaine

def EstImprimable(caractere):
    """
    Liste des caractères imprimables :
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
    Retourne le nième champ de 'chaine', séparé par 'separation'.
    Si le champ est numérique, les zéros initiaux sont retirés et on retourne un int.
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

    # Vérifie si c'était le dernier champ
    if compteur != n:
        return None

    # Si le champ est composé uniquement de chiffres, le convertir en int
    if champ.isdigit():
        return int(champ)
    return champ

def Format(n):
    """
    Retourne une chaîne de 4 caractères pour tout nombre entier de 0 à 9999,
    avec des zéros initiaux si nécessaire.
    """
    if not (0 <= n <= 9999):
        raise ValueError("Le nombre doit être compris entre 0 et 9999")
    return f"{n:04d}"

def toTab(strMessage):
    """
    Encode une chaine en tableau d'octets. l'encodage utilisé est "utf-8
    """
    return strMessage.encode('utf-8')

def toStr(strMessage):
    """
    Decode un tableau d'octets en chaine utf-8
    """
    return strMessage.decode('utf-8')

def ListeClesFromFile(nomFichier):
    """
    Lit un fichier texte contenant une clé par ligne.
    Retourne une liste de chaînes (clés).
    Essaie plusieurs encodages courants puis, en dernier ressort,
    lit en binaire et décode avec 'replace' pour éviter UnicodeDecodeError.
    """
    encodings_to_try = ['utf-8', 'cp1252', 'iso-8859-1']

    for enc in encodings_to_try:
        try:
            with open(nomFichier, 'r', encoding=enc, errors='strict') as fichier:
                # lecture simple et nettoyage
                listeCles = [ligne.strip() for ligne in fichier if ligne.strip()]
            return listeCles
        except UnicodeDecodeError:
            # on essaie l'encodage suivant
            continue

    # fallback sûr : lire en binaire et décoder en remplaçant les octets invalides
    listeCles = []
    with open(nomFichier, 'rb') as f:
        for raw in f:
            # decode en utf-8 mais remplace les octets invalides par �
            ligne = raw.decode('utf-8', errors='replace').strip()
            if ligne:
                listeCles.append(ligne)
    return listeCles


def AttaqueDictionnaire(tabMessage, listeCles, mode):
    """
    Attaque par dictionnaire sur un message chiffré avec XOR ou AES-ECB
    tabMessage : tableau d'octets chiffré
    listeCles : liste de chaînes (clés possibles)
    mode : "XOR" ou "AES"
    Retourne la clé trouvée ou None si aucune clé n'a permis de déchiffrer un message
    avec uniquement des caractères imprimables.
    """
    for cle in listeCles:
        if mode == "XOR":
            decrypted = DecodeXor(tabMessage, cle.encode())
        elif mode == "AES":
            key_bytes = cle.encode()
            if len(key_bytes) != 16:
                continue
            decrypted = DecodeAES_ECB(tabMessage, list(key_bytes))
        else:
            raise ValueError("Mode inconnu. Utilisez 'XOR' ou 'AES'.")

        if all(EstImprimable(chr(b)) for b in decrypted):
            return cle
    return None
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
    Fonction prenant en argument le message et la taille de la clé et qui brute force la clé
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
    Bruteforce la clé d'un message tabMessage crypté en Xor avec une taille de clé allant jusqu'a upperkeysize
    Retourne une liste contenant la clé trouvée
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



def main():
    import sys
    print(sys.version)
    cle="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    msg="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "*len(cle)
    msgCompteur = AjoutCompteur(msg,42)
    msgSalage = Salage(msgCompteur.encode())
    
    msgxor=EncodeXor(msgSalage,cle.encode())
    
    #tab=ForceBruteXor(msgxor,52)
    #print(tab)
    '''msg = "Coucou"
    key = "AAA".encode()
    msgCompteur = AjoutCompteur(msg,42)
    msgSalage = Salage(msgCompteur.encode())
    print("Message salé :", msgSalage)
    print("XOR encodé base64 :", EncodeBase64(EncodeXor(msgSalage,key)))
    
    # Cipher AES sans base64
    tabKey = [161, 216, 149, 60, 177, 180, 108, 234, 176, 12, 149, 45, 255, 157, 80, 136]
    msgAES_bytes = EncodeAES_ECB(msgSalage, tabKey)   # <-- conserver bytes
    print("AES ciphertext (raw bytes) :", msgAES_bytes)
    print("AES ciphertext base64 pour affichage :", EncodeBase64(msgAES_bytes))  # facultatif pour afficher
    
    # Attaque dictionnaire sur bytes, pas sur base64
    # msgAES_bytes : ciphertext AES en bytes (pas base64)
    result = AttaqueDictionnaire(msgAES_bytes, ListeClesFromFile("francais.txt"), "AES")
    if result is None:
        print("[*] Aucune clé trouvée dans la liste.")
    else:
        print("[+] Clé trouvée :", result)
        # afficher le plaintext pour vérification
        plaintext = DecodeAES_ECB(msgAES_bytes, list(result.encode()))
        print("[+] Plaintext :", plaintext)'''


def tests():
    print(EncodeXor("Bonjour".encode(),"A".encode())==b'\x03./+.43')
    print(DecodeXor(b"\n'..-","B".encode()).decode()=="Hello")
    print(EncodeXor(b"GoodBye",b"ABA")==b'\x06-.%\x008$')
    print(DecodeXor(b'\x0e42;8',b"ZWZ")=="Tchao".encode())
    print(Indice([1,2,3,4,5,6],3)==2)
    print(EncodeBase64(b"Une Chaine")==b"VW5lIENoYWluZQ==")
    print(DecodeBase64("VW5lIENoYWluZQ==")==b"Une Chaine")
    print(EncodeAES_ECB("Elements",[161, 216, 149, 60, 177, 180, 108, 234, 176, 12, 149, 45, 255, 157, 80, 136])==b'Z\xf5T\xef\x9f\x8bg\x15\xb3E\xe7&gm\x96\x1d')
    print(DecodeAES_ECB(b'Z\xf5T\xef\x9f\x8bg\x15\xb3E\xe7&gm\x96\x1d',[161, 216, 149, 60, 177, 180, 108, 234, 176, 12, 149, 45, 255, 157, 80, 136]).strip()==b"Elements")
    print(Contient("OK","Le resultat est OK !")==True)
    print(Contient("OK","Le resultat est Ok !")==False)
    print(EstImprimable("A")==True)
    print(EstImprimable("\x07")==False)
    print(EstImprimable(" ")==True)
    print(Remplace("Ceci est une string typique","string","chaine")=="Ceci est une chaine typique")
    print(Extraire("ROUGE,0034,4EF563",",",1)==34)
    print(Format(3)=="0003")
    print(Format(123)=="0123")
    print(toStr(b"\x41\x42")=="AB")
    print(toTab("CD")==b"\x43\x44")
    return

if __name__ == '__main__':
    main()