import socket
import random
import math
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib

# подключаемся к серверу
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
    server.connect(('localhost', 8080))

    # авторизация на сервере
    ID = input("Введите логин: ")
    server.send(ID.encode())
    # получение ответа от сервера и ввод пароля
    challenge = server.recv(1024)
    password = input("Введите пароль: ")

    # создание ключа шифрования из пароля
    key = hashlib.sha256(password.encode()).digest()
    IV = 16 * '\x00'
    encryptor = AES.new(key, AES.MODE_CFB, IV)
    response = encryptor.encrypt(challenge)
    # Отправляется ответ на сервер
    server.send(response)
    data = server.recv(1024)
    print(data)
    # получен ответ о том, правильный ли был введён пароль. Если нет, соединение с сервером прерывается
    if data == "Пароль неверный!":
        break

    # генерация ключа сессии
    g = 5
    p = 23
    server.send(str(g).encode())
    server.send(str(p).encode())

    # создание секретной части а
    a = 6
    print("Секретное значение а:".encode() + str(a).encode())
    A = (g ** a) % p  # g^a mod(p)
    server.send(str(A).encode())
    hashA = hashlib.sha256(str(A).encode()).digest()

    file = open("publickey1.pem", "r")
    RSAkey1 = file.read()
    file.close()

    # раскодирование данных из файла с публичным ключом
    signA = RSAkey1.encode().encrypt(hashA, 32)
    server.send(signA[0])
    print("g:".encode() + str(g).encode())
    print("p:".encode() + str(p).encode())
    print("A:".encode() + str(A).encode())
    print("signA:".encode() + signA[0])
    print("Данные отправлены серверу".encode())

    # берём приватный ключ №2
    file = open("privatekey2.pem", "r")
    RSAkey2 = file.read()
    file.close()
    RSAkey2 = RSA.importKey(RSAkey2)

    # Секретное значение B для ключа сессии получено от сервера
    B = server.recv(1024)
    signB = server.recv(1024)
    print("Значение b получено".encode())
    print("B:".encode() + str(B).encode())
    print("signB".encode() + signB)

    # Проверка значений
    hashB = hashlib.sha256(B).digest()
    checkHash = RSAkey2.decrypt(signB)
    print("hashB:".encode() + hashB)
    print("CheckHashB:".encode() + checkHash)

    if hashB == checkHash:
        print("Проверка пройдена успешно!".encode())

        # Так сервер отправил правильное секретное значение, можно сгенерировать ключ сессии
        sessionKey = str((int(B) ** a) % p)
        print("Ключ сессии сгенерирован успешно:".encode() + sessionKey)
    else:
        print("Проверка хэша не пройдена, невозможно сгенерировать ключ сессии!".encode())
        break

    # Получаем зашифрованный файл от сервера. Используем ключ сессии для его расшифровки и чтения
    encryptedEMR = server.recv(1024)
    print("Файл получен".encode())

    # расшифровка
    sessionKey = hashlib.sha256(sessionKey).digest()
    decryptor = AES.new(sessionKey, AES.MODE_CFB, IV)
    decryptedEMR = decryptor.decrypt(encryptedEMR)
    print("Decrypted EMR:".encode() + decryptedEMR)
    break
