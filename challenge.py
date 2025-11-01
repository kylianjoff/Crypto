BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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
    Chiffrement AES-ECB 128 bits de strMessage avec tabKey comme clef
    La taille de chaine est quelconque et sera complété par des caractères espace si nécessaire
    tabKey est un tableau de 16 éléments
    Avant chiffrement la chaine est encodée en utf8
    """

def DecodeAES_ECB(strMessage, tabKey):
    """
    Dechiffrement AES-ECB de strMessage
    La clef tabKey est un tableau de 16 éléments
    Retourne un tableau d'octets
    Les caractères espaces en fin de tableau seront supprimés
    """

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

def Extraire(chaine,separation,n):
    """
    Retourne la valeur du nième champ de chaine.
    Les champs sont séparés par le caractère séparation.
    """

def Format(n):
    """
    Retourne une chaine de caractères de 4 caractères pour tout nombre entier de 0 à  9999
    Les valeurs seront précédées de 0.
    """

def toTab(strMessage):
    """
    Encode une chaine en tableau d'octets. l'encodage utilisé est "utf-8
    """

def toStr(strMessage):
    """
    Decode un tableau d'octets en chaine utf-8
    """

def main():
    import sys
    print(sys.version)
    print(EncodeXor("Bonjour".encode(),"A".encode())==b'\x03./+.43')
    print(DecodeXor(b"\n'..-","B".encode()).decode()=="Hello")
    print(EncodeXor(b"GoodBye",b"ABA")==b'\x06-.%\x008$')
    print(DecodeXor(b'\x0e42;8',b"ZWZ")=="Tchao".encode())
    print(Indice([1,2,3,4,5,6],3)==2)
    print(EncodeBase64(b"Une Chaine")==b"VW5lIENoYWluZQ==")
    print(DecodeBase64("VW5lIENoYWluZQ==")==b"Une Chaine")
    #print(EncodeAES_ECB("Elements",[161, 216, 149, 60, 177, 180, 108, 234, 176, 12, 149, 45, 255, 157, 80, 136])==b'Z\xf5T\xef\x9f\x8bg\x15\xb3E\xe7&gm\x96\x1d')
    #print(DecodeAES_ECB(b'Z\xf5T\xef\x9f\x8bg\x15\xb3E\xe7&gm\x96\x1d',[161, 216, 149, 60, 177, 180, 108, 234, 176, 12, 149, 45, 255, 157, 80, 136]).strip()==b"Elements")
    print(Contient("OK","Le resultat est OK !")==True)
    print(Contient("OK","Le resultat est Ok !")==False)
    print(EstImprimable("A")==True)
    print(EstImprimable("\x07")==False)
    print(EstImprimable(" ")==True)
    print(Remplace("Ceci est une string typique","string","chaine")=="Ceci est une chaine typique")
    #print(Extraire("ROUGE,0034,4EF563",",",1)==34)
    #print(Format(3)=="0003")
    #print(Format(123)=="0123")
    #print(toStr(b"\x41\x42")=="AB")
    #print(toTab("CD")==b"\x43\x44")
    return

if __name__ == '__main__':
    main()