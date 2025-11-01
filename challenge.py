BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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
    Encode en Base64 le paramètre chaine
    tabMessage contient le message sous forme de tableau d'octets
    Retourne un tableau d'octets
    """
    result = ""
    padding = 0
    # Traiter les octets 3 par 3
    for i in range(0, len(tabMessage), 3):
        chunk = data[i:i+3]

        if len(chunk) < 3:
            padding = 3 - len(chunk)
            chunk += b'\x00' * padding

        # Convertir les 3 octets en 24 bits
        bits = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]

        # Extraire 4 groupes de 6 bits
        for j in range(18, -1, -6):
            index = (bits >> j) & 0x3F
            result += BASE64_ALPHABET[index]

    # Remplacer par '=' selon le padding
    if padding:
        result = result[:-padding] + '=' * padding

    return result

def DecodeBase64(strMessage):
    """
    Decode la chaine encodé en Base64
    strMessage doit être une chaine ASCII elle sera encodé en utf-8
    retourne un tableau d'octets
    """
    padding = strMessage.count('=')
    strMessage = strMessage.rstrip('=')
    decoded_bytes = bytearray()

    # Traiter les caractères 4 par 4
    for i in range(0, len(strMessage), 4):
        chunk = strMessage[i:i+4]
        # Convertir chaque caractère en 6 bits
        bits = 0
        for c in chunk:
            bits = (bits << 6) + BASE64_ALPHABET.index(c)

        # Extraire les 3 octets
        for j in range(16, -1, -8):
            byte = (bits >> j) & 0xFF
            decoded_bytes.append(byte)

    # Supprimer les octets ajoutés à cause du padding
    if padding:
        decoded_bytes = decoded_bytes[:-padding]

    return bytes(decoded_bytes)



def main():
    import sys
    print(sys.version)
    print(EncodeXor("Bonjour".encode(),"A".encode())==b'\x03./+.43')
    print(DecodeXor(b"\n'..-","B".encode()).decode()=="Hello")

if __name__ == '__main__':
    main()