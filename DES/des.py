# 
# Author - Shuber Ali Mirza
# ID ----- 20027047
# 

import math
import sys

# Initial permutation table
initPerm = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

# Permutation done after each round in f Function
permutationP = [16,  7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2,  8, 24, 14, 32, 27,  3,  9,
                19, 13, 30,  6, 22, 11,  4, 25]

# Expanding 32 bit right side to 48 bit
expansionE = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5,
              6 , 7 , 8 , 9 , 8 , 9 , 10, 11,
              12, 13, 12, 13, 14, 15, 16, 17,
              16, 17, 18, 19, 20, 21, 20, 21,
              22, 23, 24, 25, 24, 25, 26, 27,
              28, 29, 28, 29, 30, 31, 32, 1 ]

# Subtitution boxes
sbox =  [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]],
            
         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
           [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]],
   
         [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
           [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
           [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]],
         
          [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
           [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
           [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ],
        
          [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
           [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
           [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]],
       
         [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
           [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ],

          [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
           [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ],
        
         [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final permutation table
finalPerm = [ 40, 8, 48, 16, 56, 24, 64, 32,
             39, 7, 47, 15, 55, 23, 63, 31,
             38, 6, 46, 14, 54, 22, 62, 30,
             37, 5, 45, 13, 53, 21, 61, 29,
             36, 4, 44, 12, 52, 20, 60, 28,
             35, 3, 43, 11, 51, 19, 59, 27,
             34, 2, 42, 10, 50, 18, 58, 26,
             33, 1, 41, 9, 49, 17, 57, 25 ]

# Used in reducing size of 64 bit key to 56 bits with permuted choice 1 table
pc1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4 ]

# Used in reducing size of 56 bit key to 48 bits with permuted choice 2 table
pc2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32 ]

# Function to convert keyboard characters to binary
def char2bin(string):
    binary = ''
    for i in string:
        b = bin(ord(i))[2:]
        num = 8 - len(b)
        binary += ('0' * num) + b
    return binary

# Function to convert binary to keyboard characters
def bin2char(string):
    text = ''
    try:
        for i in range(len(string)):
            charBin = string[i*8:(i*8+8)]
            text += chr(int(charBin, 2))
    except ValueError:
        pass
    return text

# Function to convert binary to hexadecimal
def bin2hex(string):
    numChar = len(string) / 8
    hx = hex(int(string, 2))[2:]
    if len(hx) % 2 == 1:
        hx = '0' + hx
    return hx

# Function to convert hexadecimal to binary
def hex2bin(string):
    binary = ''
    try:
        for i in range(len(string)):
            charHex = string[i*2:(i*2+2)]
            b = bin(int(charHex, 16))[2:]
            num = 8 - len(b)
            binary += ('0' * num) + b
    except ValueError:
        pass
    return binary

# bits = binary string, n = number of bits you want in each split section
def splitBits(bits, n):
    arr = []
    numOfBlocks = math.ceil(len(bits)/n)
    for i in range(numOfBlocks):
        arr.append(bits[(i*n):(i*n+n)])
    return arr

# Function to pad last block of plaintext binary array to make it 64 bits. Padded using 0s and 1s alternately
# binArr = array of plainext, already converted to binary and split into array of blocks. 
def plainPad(binArr):
    padding = ''
    for i in range(64-len(binArr[-1])):
        if i%2 == 0:
            padding += '0'
        else:
            padding += '1'
    binArr[-1] += padding

# takes the main key, does required padding/chopping, and returns in binary form
def keyCreate(key):
    k = char2bin(key)
    k1 = splitBits(k, 64)
    kFinal = ''
    # If key size > 64 bits, alternate between first 64 bits, and bits in the last block
    if (len(k1[0]) == 64) and (len(k1) > 1):
        for i in range(len(k1[-1])):
            if i%2 == 0:
                kFinal += k1[0][i]
            else:
                kFinal += k1[-1][i]
        kFinal += k1[0][len(k1[-1]):]
    # If key size < 64 bits, pad it with 0s and 1s alternately
    elif len(k1[0]) < 64:
        kFinal = k1[0]
        for i in range(64-len(k1[0])):
            if i%2 == 0:
                kFinal += '0'
            else:
                kFinal += '1'
    else:
        kFinal = k1[0]
    return kFinal

# Function for permutation
# block = string of bits, t = type of permutation.
def permutate(block, t):
    final = ''
    # i = initial permutation
    if t == 'i':
        for i in range(64):
            final += block[initPerm[i]-1]
    # r = right-hand side expansion
    elif t == 'r':
        for i in range(48):
            final += block[expansionE[i]-1]
    # pc1 = permuted choice 1
    elif t == 'pc1':
        for i in range(56):
            final += block[pc1[i]-1]
    # pc2 = permuted choice 2
    elif t == 'pc2':
        for i in range(48):
            final += block[pc2[i]-1]
    # rp = round permutation
    elif t == 'rp':
        for i in range(32):
            final += block[permutationP[i]-1]
    # f = final permutation
    elif t == 'f':
        for i in range(64):
            final += block[finalPerm[i]-1]
    return final

# Function for key bitshifting 
# key = 56 bit key, rl = 'r' or 'l', roundNum = number of round from 0-16
def keyShift(key, rl, roundNum):
    shiftn = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    cd = splitBits(key, 28)
    c = cd[0]
    d = cd[1]
    # Left shifting
    if rl == 'l':
        cNext = c[shiftn[roundNum]:] + c[:shiftn[roundNum]]
        dNext = d[shiftn[roundNum]:] + d[:shiftn[roundNum]]
    # Right shifting
    elif rl == 'r':
        cNext = c[(shiftn[roundNum]*-1):] + c[:(shiftn[roundNum]*-1)]
        dNext = d[(shiftn[roundNum]*-1):] + d[:(shiftn[roundNum]*-1)]
    kNext = cNext + dNext
    return kNext

# Function for sbox subtitutions
# xorRes = resulting bits after xor with expanded right-hand side block and round subkey
def sBoxSub(xorRes):
    sBits = splitBits(xorRes, 6)
    output = ''
    for i in range(8):
        row = int(sBits[i][0] + sBits[i][-1], 2)
        col = int(sBits[i][1:-1], 2)
        res = sbox[i][row][col]
        out = bin(res)[2:]
        num = 4 - len(out)
        out = ('0' * num) + out
        output += out
    return output

# f Function. expands rightside of the round, xors with subkey, uses sbox to reduce size, and round permutation
def fFunction(rightside, subkey):
    # right side expansion E
    rExpanded = permutate(rightside, 'r')
    # xoring expanded right side and subkey
    x = bin(int(rExpanded, 2) ^ int(subkey, 2))[2:]
    num = 48 - len(x)
    x = ('0' * num) + x
    # sbox subtitution
    subed = sBoxSub(x)
    # round permutation
    perm = permutate(subed, 'rp')
    return perm

# Function for cycling the rounds
# block64 = 64 bit block, key56 = 56 bit key, ed = 'e' or 'd', roundNum = Current round. 
# does everything for that round, returns 64 bit block for next round and 56 bit key
def rounds(block64, key56, ed, roundNum):
    # spliting 64 bit block and making current right side left side for next round
    round1 = splitBits(block64, 32)
    l, r = round1[0], round1[1]
    lNext = r
    # e = Encryption mode.
    if ed == 'e':
        # leftshifting 56 bit key and generating subkey using pc2 of length 48
        key56 = keyShift(key56, 'l', roundNum)
    # d = Decryption mode
    elif ed == 'd':
        # rightshifting 56 bit key and generating subkey using pc2 of length 48
        key56 = keyShift(key56, 'r', roundNum)
    subkey = permutate(key56, 'pc2')
    # f function
    perm = fFunction(r, subkey)
    # xoring result with leftside
    rNext = bin(int(perm, 2) ^ int(l, 2))[2:]
    num = 32 - len(rNext)
    rNext = ('0' * num) + rNext
    # next round's 64 bit block
    roundNext = lNext + rNext
    return roundNext, key56

# Function for encrypting plaintext
# plainArr = plaintext array (converted to binary and padded), key56 = key after converted to binary and permuated with pc1
def Encrypt(plainArr, key56):
    encry = ''
    for j in range(len(plainArr)):
        # print(f'block{j}')
        b0 = permutate(plainArr[j], 'i')
        # Cycling through 16 rounds
        for i in range(16):
            b0, key56 = rounds(b0, key56, 'e', i)
            # print(f'Bits after round {i}:', b0)
            # print(f'Key after round {i}:', key56)
        b0 = splitBits(b0, 32)
        b1 = b0[1] + b0[0]
        b1 = permutate(b1, 'f')
        # print('after final perm:', b1)
        encry += b1
    hexCode = bin2hex(encry)
    return hexCode

# Function for decrypting ciphertext
# hexCipher = cipher text in hexadecimal, key56 = key after converted to binary and permuated with pc1
def Decrypt(hexCipher, key56):
    binCode = hex2bin(hexCipher)
    cipherArr = splitBits(binCode, 64)
    decry = ''
    for j in range(len(cipherArr)):
        # Performs the first round without rightshifting key, so rounds() function used after first round
        # print(f'block{j}')
        perm = permutate(cipherArr[j], 'i')
        round1 = splitBits(perm, 32)
        l, r = round1[0], round1[1]
        lNext = r
        key1 = key56
        k1 = permutate(key1, 'pc2')
        perm = fFunction(r, k1)
        rNext = bin(int(perm, 2) ^ int(l, 2))[2:]
        num = 32 - len(rNext)
        rNext = ('0' * num) + rNext
        roundNext = lNext + rNext
        b0 = roundNext
        # Cycling through 15 more times
        for i in range(1, 16):
            b0, key1 = rounds(b0, key1, 'd', i)
            # print(f'after round {i}:', b0)
        b0 = splitBits(b0, 32)
        b1 = b0[1] + b0[0]
        b1 = permutate(b1, 'f')
        # print('after final perm:', b1)
        decry += b1
    plaintext = bin2char(decry)
    # Removing padding from plaintext
    chopped = False
    while chopped == False:
        if plaintext[-1] == 'U':
            plaintext = plaintext[:-1]
        else:
            chopped = True
    return plaintext

# Main function
if __name__ == '__main__':
    option = None
    print('''1 - Encrypt File
2 - Encrypt Text
3 - Decrypt File
4 - Decrypt Text
0 - Quit''')
    while option != '0':
        option = input('Select option > ')
        if option == '0':
            print('Bye !!!')
        elif option == '1' or option == '2' or option == '3' or option == '4':
            key = input('Enter key > ')
            # converting key to binary and performing appropriate padding/chopping to the bits
            kPadded = keyCreate(key)
            key0 = permutate(kPadded, 'pc1')
            if option == '1' or option == '2':
                try:
                    if option == '1':
                        plainFile = input('Enter filename > ')
                        with open(plainFile, 'r') as f:
                            text = f.read()
                    elif option == '2':
                        text = input('Type text to encrypt > ')
                    # Converting plaintext to binary
                    binary = char2bin(text)
                    # spliting binary plaintext into 64 bit blocks
                    arr = splitBits(binary, 64)
                    # padding last binary block of plaintext to make it 64 bits
                    plainPad(arr)
                    # Encrypting plaintext with key
                    cipher = Encrypt(arr, key0)
                    with open('encrypted.txt', 'w') as f:
                        f.write(cipher)
                    print('Cipher written to encrypted.txt\n')
                    # print(cipher + '\n')
                except FileNotFoundError:
                    print('ERROR - File not found\n')
            elif option == '3' or option == '4':
                try:
                    if option == '3':
                        cipherFile = input('Enter filename > ')
                        with open(cipherFile, 'r') as f:
                            cipher = f.read()
                    elif option == '4':
                        cipher = input('Type cipher to decrypt > ')
                    # Decrypting cipher with key
                    text = Decrypt(cipher, key0)
                    with open('decrypted.txt', 'w') as f:
                        f.write(text)
                    print('Plaintext written to decrypted.txt\n')
                    # print(text + '\n')
                except FileNotFoundError:
                    print('ERROR - File not found\n')
        else:
            pass
