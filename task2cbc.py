import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import string
import random
import math

# Converts an integer list to a single string
def convertIntLstToString(lst):
   newlst = []
   for i in lst:
      char = chr(i)
      newlst.append(char)
   return "".join(newlst)

# Takes two strings and XOR's them if they are the same length
# If different length it throws an error
def xor(str1, str2):
   if(len(str1) != len(str2)):
      err = "Error: String length's differ:\n" + "\tstr1:" + str1 + "\n\tstr2:" + str2
      return err
   datalist = [(ord(a) ^ ord(b)) for a,b in zip(str1,str2)]
   return convertIntLstToString(datalist)

def pad(data):
   length = len(data)
   # Each block of data is 16 bytes. To get the remaining pad bytes the below equation is used
   padBytes = 16 - (length % 16)
   for i in range(0, padBytes):
      data = data + chr(padBytes)
   return data

def decryptData(data, key, iv):
   cipher = AES.new(key, AES.MODE_ECB)

   length = len(data)

   # 16 bytes in a block. And length is given in bytes
   numBlocks = length / 16

   # initializing variables
   totalDecrypt = ""
   message = ""
   xormessage = ""

   # Decrypt with CBC
   for i in range(0, numBlocks):
      message = data[i*16: i*16 + 16]
      decryptMessage = cipher.decrypt(message)
      xormessage = xor(iv, decryptMessage)
      totalDecrypt += xormessage
      iv = message
   return totalDecrypt

def encryptData(data, key, iv):
   cipher = AES.new(key, AES.MODE_ECB)

   length = len(data)

   # 16 bytes in a block. And length is given in bytes
   numBlocks = length / 16

   # initializing variables
   totalEncrypt = ""
   message = ""
   xormessage = ""

   # Encrypt with CBC
   for i in range(0, numBlocks):
      message = data[i*16: i*16 + 16]
      xormessage = xor(iv, message)
      encryptMessage = cipher.encrypt(xormessage)
      totalEncrypt += encryptMessage
      iv = encryptMessage
   return totalEncrypt

def findSHA256(hash_string):
   sha256 = hashlib.sha256(hash_string.encode()).hexdigest()
   return sha256

def findB(p, g):
   b = 11
   A = pow(g, b, p)
   return A

def findA(p, g):
   a = 7
   A = pow(g, a, p)
   return A

def truncate(val):
   return val[0:16]

def malloryInterceptA_B(p,g):
   iv = get_random_bytes(16)
   A = findA(p,g)
   B = findB(p,g)

   # Mallory Modifies A->p and B->p
   A = p
   B = p
   # Mallory knows the key = 0
   shaMa =(findSHA256(str(0)))
   malKey = (truncate(shaMa))

   sa = findA(p,B)
   sb = findB(p,A)

   shasa = (findSHA256(str(sa)))
   shasb = (findSHA256(str(sb)))

   ka = (truncate(shasa))
   kb = (truncate(shasb))

   # Padding the string
   data = pad("Hi Bob!")

   # Encryption of the string from Alice
   encrypt = encryptData(data, ka, iv)

   # Mallory intercepting the message
   decrypt = decryptData(encrypt, malKey, iv)
   print("Intercepted message by Mallory")
   print(decrypt)

   # Bob's decryption of the string from Alice
   decrypt = decryptData(encrypt, kb, iv)
   print("Message received by Bob")
   print(decrypt)

def malloryInterceptG(p,g):
   iv = get_random_bytes(16)
   A = findA(p,g)
   B = findB(p,g)

   # Mallory knows the key = 1 for 1 % (num != 1)
   shaMa =(findSHA256(str(1)))
   malKey = (truncate(shaMa))

   sa = findA(p,B)
   sb = findB(p,A)

   shasa = (findSHA256(str(sa)))
   shasb = (findSHA256(str(sb)))

   ka = (truncate(shasa))
   kb = (truncate(shasb))

   # Padding the string
   data = pad("Hi Bob!")

   # Encryption of the string from Alice
   encrypt = encryptData(data, ka, iv)

   # Mallory intercepting the message
   decrypt = decryptData(encrypt, malKey, iv)
   print("Intercepted message by Mallory")
   print(decrypt)

   # Bob's decryption of the string from Alice
   decrypt = decryptData(encrypt, kb, iv)
   print("Message received by Bob")
   print(decrypt)

def malloryInterceptP_1(p,g):
   iv = get_random_bytes(16)
   A = findA(p,g)
   B = findB(p,g)

   # Mallory knows the key = p - 1 from alegbra
   shaMa =(findSHA256(str(p - 1)))
   malKey = (truncate(shaMa))

   sa = findA(p,B)
   sb = findB(p,A)

   shasa = (findSHA256(str(sa)))
   shasb = (findSHA256(str(sb)))

   ka = (truncate(shasa))
   kb = (truncate(shasb))

   # Padding the string
   data = pad("Hi Bob!")

   # Encryption of the string from Alice
   encrypt = encryptData(data, ka, iv)

   # Mallory intercepting the message
   decrypt = decryptData(encrypt, malKey, iv)
   print("Intercepted message by Mallory")
   print(decrypt)

   # Bob's decryption of the string from Alice
   decrypt = decryptData(encrypt, kb, iv)
   print("Message received by Bob")
   print(decrypt)


def main():
   pstr = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

   gstr = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

   p = int(pstr, 16)
   g = int(gstr, 16)

   print("Mallory Changing A = p, B = p")
   malloryInterceptA_B(p,g)

   g = 1
   print("Mallory Changing g = 1")
   malloryInterceptG(p,g)

   g = p
   print("Mallory Changing g = p")
   malloryInterceptA_B(p,g)

   g = p - 1
   print("Mallory Changing g = p - 1")
   malloryInterceptP_1(p,g)

if __name__== "__main__":
   main()
