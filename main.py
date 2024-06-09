from urllib.parse import quote
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def padText(plaintext):
    padLen = 16 - len(plaintext) % 16
    padding = bytes([padLen] * padLen)
    return plaintext + padding

def unpadText(paddedText):
    padLen = paddedText[-1]
    return paddedText[:-padLen]

def ecbEncrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    paddedText = padText(plaintext)
    ciphertext = b''
    for i in range(0, len(paddedText), 16):
        block = paddedText[i:i+16]
        ciphertext += cipher.encrypt(block)
    return ciphertext

def ecbDecrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += cipher.decrypt(block)
    return unpadText(plaintext)

def cbcEncrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    paddedText = padText(plaintext)
    ciphertext = b''
    previousBlock = iv
    for i in range(0, len(paddedText), 16):
        block = paddedText[i:i+16]
        block = bytes([a ^ b for a, b in zip(block, previousBlock)])
        encryptedBlock = cipher.encrypt(block)
        ciphertext += encryptedBlock
        previousBlock = encryptedBlock
    return ciphertext

def cbcDecrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    previousBlock = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decryptedBlock = cipher.decrypt(block)
        plaintextBlock = bytes([a ^ b for a, b in zip(decryptedBlock, previousBlock)])
        plaintext += plaintextBlock
        previousBlock = block
    return unpadText(plaintext)

def task1(): 
    key = get_random_bytes(16)
    
    with open('mustang.bmp', 'rb') as f:
        header = f.read(54)
        data = f.read()

    # encrypt
    ecbCiphertext = ecbEncrypt(data, key)
    with open('mustang_ecb_encrypted.bmp', 'wb') as f:
        f.write(header + ecbCiphertext)

    iv = get_random_bytes(16)
    cbcCiphertext = cbcEncrypt(data, key, iv)
    with open('mustang_cbc_encrypted.bmp', 'wb') as f:
        f.write(header + iv + cbcCiphertext)


    # decrypt to make sure it matches originals
    with open('mustang_ecb_encrypted.bmp', 'rb') as f:
        f.read(54) 
        ecbCiphertext = f.read()
    decryptedEcb = ecbDecrypt(ecbCiphertext, key)
    if decryptedEcb != data :
        print('ECB encryption failed')
    else : 
        print('ECB encryption successful')
    
    with open('mustang_cbc_encrypted.bmp', 'rb') as f:
        f.read(54)  
        iv = f.read(16)
        cbcCiphertext = f.read()
    decryptedCbc = cbcDecrypt(cbcCiphertext, key, iv)
    if decryptedCbc != data: 
        print('CBC encryption failed')
    else : 
        print('CBC encryption successful')

def submit(input, key, iv):
    userInput = quote(input)
    fullString = f'userid=456;userdata={userInput};session-id=31337'
    return cbcEncrypt(fullString.encode(), key, iv)

def verify(encryptedString, key, iv):
    decryptedString = cbcDecrypt(encryptedString, key, iv)
    if b'admin=true' in decryptedString: 
        print('USER IS ADMIN')
        return True
    else: 
        print('USER IS NOT ADMIN')
        return False
    

def modifyCiphertext(encrypted, targetPosition, originalChar, targetChar):
    xorDiff = ord(targetChar) ^ ord(originalChar)
    
    blockIndex = targetPosition // 16
    byteIndex = targetPosition % 16
    
    modifiedEncrypted = bytearray(encrypted)
    
    prevBlockStart = (blockIndex - 1) * 16
    modifiedEncrypted[prevBlockStart + byteIndex] ^= xorDiff
    return bytes(modifiedEncrypted)
    
def task2(): 
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # does not find admin 
    print('Example 1:')
    userInput = 'You’re the man now, dog'
    encryptedText = submit(userInput, key, iv)
    verify(encryptedText, key, iv)
    print('\n')

    print('Example 2:')
    userInput = 'admin=true'
    encryptedText = submit(userInput, key, iv)
    verify(encryptedText, key, iv)
    print('\n')

    print('Example 3:')
    userInput = 'admin9true'
    encryptedText = submit(userInput, key, iv)
    verify(encryptedText, key, iv)
    print('\n')


    
    # attack that injects ;admin=true; into decrypted text
    # input used for attack to work is "admin9true"
    print('Attack results:')
    userInput = 'admin9true'
    encryptedText = submit(userInput, key, iv)
    #put ; before admin9true;
    modifiedText = modifyCiphertext(encryptedText, 19, '=', ';')
    # change 9 to = in ;admin9true;
    modifiedText = modifyCiphertext(modifiedText, 25, '9', '=')
    verify(modifiedText, key, iv)


def main():
    #task1()
    task2()

    

if __name__ == '__main__':
    main()
