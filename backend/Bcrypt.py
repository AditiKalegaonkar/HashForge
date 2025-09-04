import SHA256
import os
import random
import string

class Bcrypt:
    def __init__(self, cost=12,salt_length = 0):
        self.cost = cost
        self.salt_length = salt_length

    # Actual base_64 encoding function to encode generated salt
    def base64_encode(self, data=None):
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        binary_str = ''.join(f'{ord(c):08b}' for c in data)
        padding_len = (6 - len(binary_str) % 6) % 6
        binary_str += '0' * padding_len
        encoded = ''
        for i in range(0, len(binary_str), 6):
            chunk = binary_str[i:i+6]
            index = int(chunk, 2)
            encoded += base64_chars[index]

        padding = '=' * ((4 - len(encoded) % 4) % 4)
        return encoded + padding
    
    # Encoding into single character for salt and cost
    def base64_encode_single_char(self,data):
        data = int(data)
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return base64_chars[data]
    
    # Decoding the single character for salt and cost
    def base64_decode_single_char(self, encoded):
        base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return base64_chars.index(encoded)

    # Salt generation
    def generating_salt(self, salt_len=None):
        random.seed(salt_len)
        characters = string.ascii_letters + string.digits  
        return ''.join(random.choice(characters) for _ in range(int(salt_len)))

    # Actual hash creation by iterating using SHA256
    def hash_creation(self, password, salt, cost):
        cost = self.cost
        password_final = password + salt
        hashed  = SHA256.sha256(password_final) 
        rounds = 2**int(cost) 
        while(rounds):
            hashed = SHA256.sha256(str(hashed))
            rounds -= 1  
        return hashed
    
    # Left rotation for decoding
    def rotate_left(self,s, n):
        n = n % len(s)
        return s[n:] + s[:n]

    # Right rotation for encoding 
    def rotate_right(self,s, n):
        n = n % len(s)
        return s[-n:] + s[:-n]

    # Encoding salt and cost values in the hash
    def encode(self,arr,password_length,hash):
        mod = hash  
        for i in range(len(arr)):
            mod = self.rotate_right(mod, password_length) 
            mod = mod + self.base64_encode_single_char(arr[i])  
        return mod

    # Decoding salt and cost values from the hash
    def decode(self,res,password_length):
        ans = []
        for _ in range(2):
            ans.append(self.base64_decode_single_char(res[-1]))
            res = res[:-1]
            res = self.rotate_left(res,password_length)
        return ans,res

    # Hashing the entire password and encoding
    def hash_password(self, password,salt_len = None,cost = None):
        if salt_len == None: 
            salt_len = self.salt_length

        if cost == None:
            cost = self.cost

        salt = self.generating_salt(salt_len)
        arr = [str(salt_len),str(cost)]
        hashed_password = self.hash_creation(password, salt, cost)
        modified = self.encode(arr,len(password),hashed_password)
        return modified

    # Decoding from hash created and verifying with new user input
    def verify(self, new_password, hashed_password):
        ans, hashed = self.decode(hashed_password,len(new_password))
        cost = int(ans[0])
        salt_len = int(ans[1])
        salt = self.generating_salt(salt_len)
        return hashed == self.hash_creation(new_password, salt, cost)

bcrypt = Bcrypt()
"""password = input("Enter the password: ")
salt_len = input("Enter salt length: ")
cost = input("Enter cost: ")
hashed_password = bcrypt.hash_password(password,salt_len,cost)
print('Bcrypt Hash:', hashed_password)
new_pw = input("Enter for checking: ")
if bcrypt.verify(new_pw, hashed_password):
    print("Password is correct.")
else:
    print("Oops! Incorrect password.")"""
