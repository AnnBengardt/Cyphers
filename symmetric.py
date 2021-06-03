import math, random, datetime, hashlib


#Blockchain
class Block:

    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        sha = hashlib.sha256()
        tm = str(self.timestamp)
        sha.update((str(self.index) + tm + str(self.data) + str(self.previous_hash)).encode('utf-8'))
        return sha.hexdigest()

def create_genesis_block():
 return Block(0, datetime.datetime.now(), "Genesis Block", "0")

def next_block(last_block):
    this_index = last_block.index + 1
    this_timestamp = datetime.datetime.now()
    this_data = "Hey! I'm block " + str(this_index)
    this_hash = last_block.hash
    return Block(this_index, this_timestamp, this_data, this_hash)

  
#Caesar encryption
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

#Шифрование
def encryption_caesar(msg, offset):
    encrypted_alphabet = ALPHABET[offset:] + ALPHABET[:offset]
    encrypted = []
    for char in msg:
        index = ALPHABET.find(char)
        encrypted_char = encrypted_alphabet[index] if index >= 0 else char
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

#Расшифровка
def decryption_caesar(msg, offset):
    encrypted_alphabet = ALPHABET[offset:] + ALPHABET[:offset]
    decrypted = []
    for char in msg:
            index = encrypted_alphabet.find(char)
            encrypted_char = encrypted_alphabet[index - offset] \
                if index >= 0 else char
            decrypted.append(encrypted_char)
    return ''.join(decrypted)
    return 'Не удалось расшифровать сообщение %s' % msg

  
  
#Vigenere encryption
#Формирование словаря
def form_dict():
    d = {}
    iter = 0
    for i in range(0, 127):
        d[iter] = chr(i)
        iter = iter + 1
    return d

  
#Шифрование
def encode_val(word):
    list_code = []
    lent = len(word)
    d = form_dict()
    for w in range(lent):
        for value in d:
            if word[w] == d[value]:
                list_code.append(value)
    return list_code

  
def comparator(value, key):
    len_key = len(key)
    dic = {}
    iter = 0
    full = 0
    for i in value:
        dic[full] = [i, key[iter]]
        full = full + 1
        iter = iter + 1
        if (iter >= len_key):
            iter = 0
    return dic

  
#Создание сдвига
def full_encode(value, key):
    dic = comparator(value, key)
    print('Compare full encode', dic)
    lis = []
    d = form_dict()
    for v in dic:
        go = (dic[v][0] + dic[v][1]) % len(d)
        lis.append(go)
    return lis

  
#Расшифровка сдвигом
def full_decode(value, key):
    dic = comparator(value, key)
    print('Deshifre=', dic)
    d = form_dict()
    lis = []
    for v in dic:
        go = (dic[v][0] - dic[v][1] + len(d)) % len(d)
        lis.append(go)
    return lis

  
#Расшифровка
def decode_val(list_in):
    list_code = []
    lent = len(list_in)
    d = form_dict()
    for i in range(lent):
        for value in d:
            if list_in[i] == value:
                list_code.append(d[value])
    return list_code

  
#OTP generation
def generateOTP():
    string = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    OTP = ""
    length = len(string)
    for i in range(6):
        OTP += string[math.floor(random.random() * length)]
    return OTP

  
#Feistel network
ROUNDS = 16
KEY = 'Abcdefg'
text = 'Hello programming world'
block = []
key_pos = 0
if len(text) % 2 != 0 :
    text = text +' '
for i in range(0, len(text), 2):
    block.append(text[i:i + 2])

def festel(L,R,key_pos):
    for i in range(ROUNDS):
        k = ord(KEY[key_pos % 7::][0])
        temp = R ^ (L ^ k)
        R = L
        L = temp
        key_pos += 1
        end = (chr(R) + chr(L))
    return end,key_pos

def festel_decript(L,R, key_pos):
    for i in range(ROUNDS):
        K = ord(KEY[key_pos % 7::][0])
        temp = R ^ (L ^ K)
        R = L
        L = temp
        key_pos -= 1
        end = (chr(L) + chr(R))
    return end, key_pos

print('\nШифруем\n')
shifr = []
for x in block:
    block,key_pos = festel(ord(x[0]), ord(x[1]), key_pos)
    shifr.append(block)

print(''.join(shifr))

print('\nДешифруем\n')

defshifr=[]

key_pos -= 1

for x in shifr[::-1]:
    block,key_pos = festel_decript(ord(x[0]), ord(x[1]), key_pos)
    defshifr.append(block)
    defshifr1 = ''.join(defshifr)
print(defshifr1[::-1])
