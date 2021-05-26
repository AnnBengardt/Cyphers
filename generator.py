import socket
from Crypto import Random
from Crypto.PublicKey import RSA

# Данный файл используем для генерации ключей сессий

# генерируес последовательность
rng1 = Random.new().read
RSAkey1 = RSA.generate(1024, rng1)

privatekey1 = RSAkey1 # генерируем приватный и публичный ключи
publickey1 = RSAkey1.publickey()

# Каждый из полученных ключей записываем в файлы

f = open("privatekey1.pem", 'w')
f.write(str(privatekey1))
f.close()

f2 = open("publickey1.pem", 'w')
f2.write(str(publickey1))
f2.close()

# Генерируем всё то же самое, но для второй пары данных

rng2 = Random.new().read
RSAkey2 = RSA.generate(1024, rng2)

privatekey2 = RSAkey2
publickey2 = RSAkey2.publickey()

f3 = open("privatekey2.pem", 'w') # тоже записываем в файл
f3.write(str(privatekey1))
f3.close()

f4 = open("publickey2.pem", 'w')
f4.write(str(publickey1))
f4.close()

# Словари, хранящие данные о соединении клиента с сервером и их пары ключей
mydict1 = {'Client': privatekey1.exportKey(), 'Server': publickey1.exportKey()}
mydict2 = {'Client': publickey2.exportKey(), 'Server': privatekey2.exportKey()}

CA = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # создание подключения

CA.bind(('localhost', 9999))
CA.listen(5)
print("Сервер-генератор активен...")

while True:

    # Подключение клиента
    connection, address = CA.accept()
    print("Подключён " + address[0])

    user = connection.recv(1024)

    # проверка, какой именно ключ отправить
    for name, key1 in mydict1.items():
        if name == user:
            connection.sendall(key1)
            print("Отправлен ключ №1")
        else:
            print("В доступе отказано!")
            connection.close()

    for name, key2 in mydict2.items():
        if name == user:
            connection.sendall(key2)
            print("Отправлен ключ №2")
        else:
            print("В доступе отказано!")
            connection.close()

    CA.close()