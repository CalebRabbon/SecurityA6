# Encrypts a .bmp file with Cypher block chaining encryption

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import string

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

def encryptData(data):
   key = get_random_bytes(16)
   iv = get_random_bytes(16)
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


def main():
   p =
   g =

   # Padding the string
   data = pad(data)

   # Encryption of the string
   encrypt = encryptData(data)
   cp.write(encrypt)

if __name__== "__main__":
   main()
