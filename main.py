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

def submit(key, iv):
    userInput = quote(input("provide data\n"))
    print(userInput)
    fullString = f'userid=456;userdata={userInput};session-id=31337'
    return cbcEncrypt(fullString.encode(), key, iv)

def verify(encryptedString, key, iv):
    decryptedString = cbcDecrypt(encryptedString, key, iv).decode()
    print(f'STRING FOUND: {decryptedString}')
    if ';admin=true' in decryptedString: 
        print('admin found')
    else: 
        print('not admin')
    
def modifyEncryptedText(encryptedBytes): 
    print('modifying ecrypted text')

def task2(): 
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    encryptedText = submit(key, iv)
    verify(encryptedText, key, iv)
    modifiedText = modifyEncryptedText(encryptedText)




def main():
    #task1()
    task2()

    

if __name__ == '__main__':
    main()
