from urllib.parse import quote
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
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

def rsaPlot(): 
    keySizes = ['512', '1024', '2048', '3072', '4096', '7680', '15360']
    sign_per_sec = [57387.9, 11832.6, 1908.3, 656.2, 298.3, 36.1, 6.7]
    verify_per_sec = [601299.8, 239910.6, 74576.6, 35123.2, 20366.3, 5934.5, 1512.3]
    encrypt_per_sec = [526703.4, 223003.3, 72012.7, 34372.1, 20035.0, 5884.7, 1505.3]
    decrypt_per_sec = [46348.8, 11238.3, 1892.1, 655.0, 297.6, 36.1, 6.7]

    x = range(len(keySizes))
    width = 0.2

    fig, ax = plt.subplots()
    ax.bar(x, sign_per_sec, width, label='Sign/s')
    ax.bar([i + width for i in x], verify_per_sec, width, label='Verify/s')
    ax.bar([i + 2 * width for i in x], encrypt_per_sec, width, label='Encrypt/s')
    ax.bar([i + 3 * width for i in x], decrypt_per_sec, width, label='Decrypt/s')

    ax.set_xlabel('Key Size')
    ax.set_ylabel('Operations per Second')
    ax.set_title('OpenSSL RSA Speed Comparison')
    ax.set_xticks([i + 1.5 * width for i in x])
    ax.set_xticklabels(keySizes)
    ax.legend()

    plt.tight_layout()
    plt.savefig('openssl_rsa_speed_comparison.png')
    plt.close()

def aesPlot():
    blockSizes = ['16 bytes', '64 bytes', '256 bytes', '1024 bytes', '8192 bytes', '16384 bytes']
    aes_128_cbc = [1216244.45, 1632267.09, 1767505.75, 1810277.54, 1826346.33, 1826182.49]
    aes_192_cbc = [1070962.59, 1399145.69, 1493257.13, 1525669.59, 1534525.44, 1530658.82]
    aes_256_cbc = [635630.36, 1222691.01, 1298840.66, 1316240.35, 1323242.84, 1324826.62]

    x = range(len(blockSizes))
    width = 0.25

    fig, ax = plt.subplots()
    ax.bar(x, aes_128_cbc, width, label='AES-128-CBC')
    ax.bar([i + width for i in x], aes_192_cbc, width, label='AES-192-CBC')
    ax.bar([i + 2 * width for i in x], aes_256_cbc, width, label='AES-256-CBC')

    ax.set_xlabel('Block Size')
    ax.set_ylabel('Thousands of Bytes proccessed per second')
    ax.set_title('OpenSSL AES Speed Comparison')
    ax.set_xticks([i + width for i in x])
    ax.set_xticklabels(blockSizes)
    ax.legend()
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: '{:,.0f}'.format(x)))

    plt.tight_layout()
    plt.savefig('openssl_aes_speed_comparison.png')
    plt.close()  # Close the plot to release memory



def task3():
    rsaPlot()
    aesPlot()

def main():
    task1()
    task2()
    task3()

    

if __name__ == '__main__':
    main()
