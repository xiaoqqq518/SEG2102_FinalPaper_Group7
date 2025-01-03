import time
import psutil
from Crypto.Cipher import DES3  # imports TDES class for implementation
from Crypto.Util.Padding import pad, unpad
import os

def runTDES(dataSize):
    def encryptTDES(data, key):
        cipherObj = DES3.new(key, DES3.MODE_CBC)
        encrypted = cipherObj.encrypt(pad(data.encode(), DES3.block_size))
        return cipherObj.iv + encrypted

    def decryptTDES(encryptedData, key):
        iv = encryptedData[:DES3.block_size]
        encrypted = encryptedData[DES3.block_size:]
        cipherObj = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = unpad(cipherObj.decrypt(encrypted), DES3.block_size)
        return decrypted.decode()

    data = "Z" * dataSize
    key = os.urandom(24)    # TDES requires 24-bits key size (8 each for its encrypt-decrypt-encrypt process)

    startTime = time.time()
    encryptedData = encryptTDES(data, key)
    encryptionTime = time.time() - startTime
    if encryptionTime < 0.000001:
        encryptionTime = 0.000001

    decryptionStartTime = time.time()
    decryptedData = decryptTDES(encryptedData, key)
    decryptionTime = time.time() - decryptionStartTime

    def calcThroughput(dataSize, timeTaken):
        if timeTaken == 0:
            return 0
        return dataSize / timeTaken

    encryptionThroughput = calcThroughput(len(data), encryptionTime)
    decryptionThroughput = calcThroughput(len(data), decryptionTime)

    cpuUsage = psutil.cpu_percent(interval = 1)

    print(f"----- RESULT: TDES for {dataSize}B -----")
    print(f"Encryption Time: {encryptionTime:.6f} s")
    print(f"Decryption Time: {decryptionTime:.6f} s")
    print(f"Encryption Throughput: {encryptionThroughput:.4f} Bps")
    print(f"Decryption Throughput: {decryptionThroughput:.4f} Bps")
    print(f"CPU Usage During Encryption: {cpuUsage:.2f}%")

runTDES(64)    # EXECUTION -- simulation conducted with 64 / 1024 / 16384 / 1048576 bytes