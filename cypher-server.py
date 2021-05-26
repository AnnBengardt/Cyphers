import socket
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib

# В начале программы создаётся сокет и развёртывается сервер путём привязывания локального хоста к сокету

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind(('localhost', 8080))
print("Сокет привязан к хосту")
server.listen(5)
print("Сервер активен...")
# Сервер слушает клиентов

while True:
    # подключение клиента и получение его данных
    connection, address = server.accept()
    print("Подсоединён " + address[0])

    data = connection.recv(1024)

    env = Random.new().read(16)
    connection.sendall(env)

    # задаём пароль для входа
    password = "qwerty"
    hash_key = hashlib.sha256(password.encode()).digest()
    IV = 16 * '\x00'
    # ключ расшифровки
    decypher = AES.new(hash_key, AES.MODE_CFB, IV)

    # принимаем пароль от клиента
    response = connection.recv(1024)

    # хэшируем полученный пароль
    plain = decypher.decrypt(response)

    # проверка пароля
    if plain == env:
        connection.sendall("Добрый день!".encode())
        print("Новый вход на сервер!".encode())
    else:
        connection.sendall("Пароль неверный!".encode())
        break

    # генерация кдюча сессии
    g = connection.recv(1024)
    p = connection.recv(1024)
    A = connection.recv(1024)
    signA = connection.recv(1024)
    print("Получены ключи от клиента:".encode())
    print("g:".encode() + str(g).encode())
    print("p:".encode() + str(p).encode())
    print("A:".encode() + str(A).encode())
    print("signA:".encode() + signA)

    # получение ключей из специально подготовленного файла
    file = open("privatekey1.pem", "r")
    RSAkey1 = file.read()
    file.close()
    RSAkey1 = RSA.importKey(RSAkey1)

    checkHashA = RSAkey1.decrypt(signA) # проверка ключа
    hashA = hashlib.sha256(A).digest()

    file = open("publickey2.pem", "r")
    RSAkey2 = file.read()
    file.close()
    RSAkey2 = RSA.importKey(RSAkey2)

    print("хэш А:" + hashA)
    print("Проверка хэш А:" + checkHashA)

    # производится проверка контрольной суммы
    if hashA == checkHashA:
        print
        "Проверка пройдена успешно!"

        b = 15
        B = (int(g) ** b) % int(p)
        print("Секретное значение b:" + str(b))



        hashB = hashlib.sha256(str(B)).digest()
        signB = RSAkey2.encrypt(hashB, 32)
        # секретное значение отправляется пользователю и наконец генерируется ключ
        connection.sendall(str(B))
        connection.sendall(signB[0])
        print("B:" + str(B))
        print("signB:" + signB[0])
        print("Данные отправлены клиенту")

        sessionKey = str((int(A) ** b) % int(p))
        print("Ключ сессии сгенерирован успешно:" + sessionKey)
    else:
        print("Проверка хэша не пройдена, невозможно сгенерировать ключ сессии!")
        break

    # открываем файл, по ключу сессии зашифровываем содержимое и отправляем его клиенту
    file = open("EMR.txt", "r")
    EMRfile = file.read()
    file.close()

    sessionKey = hashlib.sha256(sessionKey).digest()
    encryptor = AES.new(sessionKey, AES.MODE_CFB, IV) # ключ шифрования

    encryptedEMR = encryptor.encrypt(EMRfile) # шифрование

    connection.send(encryptedEMR)
    print("EMR отправлено клиенту")
    print("Зашифрованный файл:" + encryptedEMR)
    break

connection.close()
server.close()