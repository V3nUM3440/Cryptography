# 
# Author - Shuber Ali Mirza
# ID ----- 20027047
# 

import random

# Extended euclidean algorithm
def egcd(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1
    # Recursion case
    else:
        gcd, x1, y1 = egcd(b % a, a)
        x = y1 - ((b // a) * x1)
        y = x1
        # Returns gcd = GCD(a, b), x = modular inverse of a, y = modular inverse of b
        return gcd, x, y

# Modular exponence: x = base, H = exponent, n = modulus
def modExp(x, H, n):
    if n == 1:
        return 0
    y = 1
    x = x % n
    while H > 0:
        if H % 2 == 1:
            y = (y * x) % n
        H = H >> 1
        x = (x**2) % n
    return y

# Lehmann's Algo (Prime Checker): p = (prime) number
def lehmann(p):
    probs = []
    # Repeated 10 times and results stored in "probs" list
    for i in range(10):
        a = random.randint(0, p)
        while a == p:
            a = random.randint(0, p)
        x = (p - 1) // 2
        r = modExp(a, x, p)
        # if modular exponence not equal to 1 or p-1, return False, meaning "Not a prime"
        if (r != 1) and (r != p-1):
            return False
        # Else add value to "prob" list
        else:
            probs.append(r)
    checkOnes = True
    # If "probs" list filled with ones, return True, else calculate probability, and if probability > 50%, return True
    for i in probs:
        if i != 1:
            checkOnes = False
    if checkOnes == False:
        probability = 1 - 1 / (2**10)
        if probability > 0.5:
            return True
        else:
            return False
    else:
        return True

# Getting a prime number between "lower" and "upper"
def getPrime(lower, upper):
    check = False
    while check == False:
        a = random.randrange((2**lower) + 1, 2**upper, 2)
        # Using the "lehmann()" function, so check if number is prime or not
        check = lehmann(a)
    return a

# Generates the public and private key using "lower" and "upper" as lower and upper bound for prime number size
def keyGen(lower, upper):
    p, q = getPrime(lower, upper), getPrime(lower, upper)
    n = p * q
    phiN = (p-1) * (q-1)
    # Getting encryption and decryption exponents = e, d
    gcd = 0
    d = -1
    while gcd != 1:
        e = getPrime(lower, upper)
        gcd, d, y = egcd(e, phiN)
        if d < 0:
            d = d + phiN
    return e, d, n

# Source Coding
# Converts string to a list of 3 digit integers in the form of strings, with leading zeros, if integer is less than 3 digits
def str2intList(string):
    chars = []
    for i in string:
        dec = str(ord(i))
        if len(dec) < 3:
            dec = '0' + str(dec)
        chars.append(dec)
    return chars

# Converts a list created by the "str2intList()" function back to string
def intList2str(intList):
    string = ''
    for i in intList:
        string += chr(int(i) % 127)
    return string

# Converts integer to hexadecimal string
def int2hex(n):
    return hex(n)[2:]

# Converts hexadecimal string to integer
def hex2int(x):
    try:
        return int(x, 16)
    except:
        return 0

# Converts "string" to list of numbers, to be used in the RSA calculation
def sourceCode(string):
    s = str2intList(string)
    blocks = []
    for i in range(len(s)):
        if i % 2 == 0:
            if (i == (len(s)-1)):
                blocks.append(s[i] + '000')
            else:
                blocks.append(s[i] + s[i+1])
    return blocks

# Encryption: message = message to be encrypted, e = encryption exponent, n = modulus
def Encrypt(message, e, n):
    blocks = sourceCode(message)
    cipherList = []
    for block in blocks:
        num = modExp(int(block), e, n)
        x = int2hex(num)
        cipherList.append(x)
    return 'g'.join(cipherList)

# Decryption: cipherText = string of hexadecimal returned by "Encryption()" function, d = decryption exponent, n = modulus
def Decrypt(cipherText, d, n):
    hexList = cipherText.split('g')
    nums = []
    for m in hexList:
        nums.append(modExp(hex2int(m), d, n))
    numList = []
    for i in nums:
        chars = str(i)
        if len(chars) < 6:
            chars = ('0' * (6 - len(chars))) + chars
        char1, char2 = chars[:3], chars[3:]
        numList.extend((char1, char2))
    return intList2str(numList)

# Creates a key file, to store public and private keys between the size of 2^lower < k <= 2^upper
def makeKeyFile(fileName, lower, upper):
    with open(fileName, 'w') as keyFile:
        e, d, n = keyGen(lower, upper)
        keyFile.write(str(e) + '\n' + str(d) + '\n' + str(n))
        print(f'Key file: {fileName} created')

# Fetches the keys from the key file
def getKeyFile(fileName):
    with open(fileName, 'r') as keyFile:
        e = int(keyFile.readline().strip())
        d = int(keyFile.readline().strip())
        n = int(keyFile.readline().strip())
    return e, d, n

# Fetches contents of a file
def getText(fileName):
    with open(fileName, 'r') as filen:
        string = filen.read()
    return string

# Encrypts contents of a file. e = encryption exponent, n = modulus
def EncryptFile(fileName, e, n):
    try:
        message = getText(fileName)
        with open('Encrypted.txt', 'w') as encry:
            cipher = Encrypt(message, e, n)
            encry.write(cipher)
            print('Cipher written to Encrypted.txt file')
    except FileNotFoundError:
        print('ERROR - File Not Found')

# Decrypts contents of a file. d = decryption exponent, n = modulus
def DecryptFile(fileName, d, n):
    try:
        cipher = getText(fileName)
        with open('Decrypted.txt', 'w') as decry:
            message = Decrypt(cipher, d, n)
            decry.write(message)
            print('Deciphered message written to Decrypted.txt file')
    except FileNotFoundError:
        print('ERROR - File Not Found')

        
if __name__ == '__main__':
    option = None
    print('''1 - Create Key File
2 - Load Key File
3 - Encrypt File
4 - Decrypt File
0 - Quit''')
    keyFile = None
    while option != '0':
        option = input('\nEnter option > ')
        if option == '1':
            fileName = input('Give key file name > ')
            lower = int(input('Lowest prime size (2^?) > '))
            upper = int(input('Highest prime size (2^?) > '))
            makeKeyFile(fileName, lower, upper)
        elif option == '2':
            keyFile = input('Give key file name > ')
            try:
                e, d, n = getKeyFile(keyFile)
                print(f'Key file: {keyFile} loaded')
            except FileNotFoundError:
                print('ERROR - File Not Found')
                keyFile = None
        elif option == '3':
            eFile = input('Enter file name > ')
            if keyFile != None:
                EncryptFile(eFile, e, n)
                print(f'Using key file: {keyFile}')
            else:
                print('ERROR - Key file not loaded')
        elif option == '4':
            dFile = input('Enter file name > ')
            if keyFile != None:
                DecryptFile(dFile, d, n)
                print(f'Using key file: {keyFile}')
            else:
                print('ERROR - Key file not loaded')
        elif option == '0':
            print('BYE!!!')
        else:
            pass
