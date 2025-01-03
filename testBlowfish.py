import time
import psutil
from Crypto.Cipher import Blowfish  # imports Blowfish class for implementation
from Crypto.Util.Padding import pad, unpad
import os

def runBlowfish(dataSize):
    def encryptBlowfish(data, key):
        cipherObj = Blowfish.new(key, Blowfish.MODE_CBC)
        encrypted = cipherObj.encrypt(pad(data.encode(), Blowfish.block_size))
        return cipherObj.iv + encrypted

    def decryptBlowfish(encryptedData, key):
        iv = encryptedData[:Blowfish.block_size]
        encrypted = encryptedData[Blowfish.block_size:]
        cipherObj = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted = unpad(cipherObj.decrypt(encrypted), Blowfish.block_size)
        return decrypted.decode()

    data = "Y" * dataSize
    key = os.urandom(16)

    startTime = time.time()
    encryptedData = encryptBlowfish(data, key)
    encryptionTime = time.time() - startTime
    if encryptionTime < 0.000001:
        encryptionTime = 0.000001

    decryptionStartTime = time.time()
    decryptedData = decryptBlowfish(encryptedData, key)
    decryptionTime = time.time() - decryptionStartTime

    def calcThroughput(dataSize, timeTaken):
        if timeTaken == 0:
            return 0
        return dataSize / timeTaken

    encryptionThroughput = calcThroughput(len(data), encryptionTime)
    decryptionThroughput = calcThroughput(len(data), decryptionTime)

    cpuUsage = psutil.cpu_percent(interval = 1)

    print(f"----- RESULT: Blowfish for {dataSize}B -----")
    print(f"Encryption Time: {encryptionTime:.6f} seconds")
    print(f"Decryption Time: {decryptionTime:.6f} seconds")
    print(f"Encryption Throughput: {encryptionThroughput:.4f} bytes/second")
    print(f"Decryption Throughput: {decryptionThroughput:.4f} bytes/second")
    print(f"CPU Usage During Encryption: {cpuUsage:.2f}%")

runBlowfish(64)     # EXECUTION -- simulation conducted with 64 / 1024 / 16384 / 1048576 bytes