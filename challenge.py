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
    print(EncodeBase64(b"Une Chaine"))
    print(DecodeBase64("VW5lIENoYWluZQ=="))

if __name__ == '__main__':
    main()