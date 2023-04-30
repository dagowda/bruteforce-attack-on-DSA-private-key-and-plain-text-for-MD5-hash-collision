from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import hashlib
import os
import io
import itertools


UID = 119151556
First_Name="dhanush"
Last_Name="devaladakere arvind"

# Location of the #'s in the below block. Remember the last location is ignored in lists so this will include 54,55 : print(key_with_error[54:56])
key_with_error='''-----BEGIN DSA PRIVATE KEY-----
MIIBuQIBAAKBgQC973oUk7##7lilY1gwPAtXvTNDWbPbQhlstbax0b6LMyPCE1xf
gwLoercCPm1OWl65pRExUR5g0CJxFZNekWQKh7fNqzMQt5fUKMMwtU4Im05M+sTb
FeVYTiUrEdWjAbF5XvN6RgcEp7rL1ZX4VucElbxoAIvek+Aqfr0Zg/ltBQIVAKoK
+9q7j+T3esxgCTQMI2BQKSQnAn8dphjfU5jwzf+Nst9rkn1tZO0afBuzvNMRS8BF
9LCJ2q2Nly9Orifz8IJqkhIGnEy802QyjUgLJAgYlBWarK1vJTQApgwN3t66mE9J
Oc3gBgi9skZ/AQimaMb8YiHskbhn85ISpgJcvkjnL2KiTA/FtwTbzAj/Z5Sqv0xK
ax2GAoGBAJpAieRPdSlKrM7x5gVlPZiI5vXEdw83IBIsK0W5XTtD5LeDfemLQDO9
Qz49svcBuH6pdINnvQ3CrxaiJyJTMnfNNK9NuBeW2Q4KZJxQflXhcNuXcG0i2m0l
QizOAkzQKKHeIMk5+7KoD3tgm4xzJvPewhaSca6upI3xVUobnjs/AhR7SchExgXv
cJMj8CVGbPRdKkKBUg==
-----END DSA PRIVATE KEY-----
'''

plain1 = b'\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x87\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\x71\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\xf2\x80\x37\x3c\x5b\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\xb4\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\xa8\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\x2b\x6f\xf7\x2a\x70'


#Incorrect inputblock
plain2 = b'\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x00\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\x00\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\x72\x80\x37\x3c\x5b\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\x34\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\x28\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\xab\x6f\xf7\x2a\x70'



#NOTE: No modifications required for this function. This will verify if your key is correct.
# This will return True if the key is correct and False if it is incorrect. Use it as it is in your bruteforce function.
def verify(key):
  try:
        possible_key = DSA.import_key(io.StringIO(key).getvalue())
        print("The key is correct :")
        print(key)
        return True
  except ValueError:
        return False


def bruteforce(key_with_error):
  # Generate all possible iterations for the given characterset for 2 characters
  # You might want to convert the string to list because strings are immutable.
  # For each possible iteration do the following:
  # 1. Modify the positions in the key (## on locations 54,55) with the characters in this iteration
  # 2. Validate the key by using verify() function.
  # 3. Return the full key if it is validated in string format not list.
  # 4. Continue if the key is invalid
  da="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
  for chara in itertools.product(da,repeat=2):#this stores aa,ab,ac..... in chara
      correct_key=key_with_error[:54]+chara[0]+chara[1]+key_with_error[56:]
  #WRITE CODE HERE

      if(verify(correct_key)):
           return(correct_key)

#Returns true if hashes match
def verify_hash(temp):
  return (hashlib.md5(plain1).digest()==hashlib.md5(temp).digest() and plain1 != temp)


def hash_collision(plain2):
    arr = bytearray(plain2) #convert b'\xaa\x1a' to 201,109
    chara="123456789abcdef"
    for i in range(256):
      for j in range(256):
          for x in range(256):
              arr[19]=i
              arr[45]=j
              arr[59]=x
              possible_hash = bytes(arr) # this is from 1,2 ro b'\01\x02'
              #possible_hash = bytes(arr)
              if (verify_hash(possible_hash)):
                 return possible_hash

  # Generate all possible iterations for the given characterset for 3 characters
  # You might want to convert the string to list because strings are immutable.
  # For each possible iteration do the following:
  # 1. Modify get the 3 bytes of each iteration and replace them in 19, 45 and 59th index
  # 2. Convert the list back to bytestring format like plain1
  # 3. Verify the modified hash and return the hash if true as given below


print(hash_collision(plain2))


#Calling the bruteforce function
new_key = bruteforce(key_with_error)
a=bruteforce(key_with_error)
print(a)