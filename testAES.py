import time     # to measure current time for timing encryption/decryption operations
import psutil   # used in measuring CPU usage
from Crypto.Cipher import AES   # imports AES class for implementation
from Crypto.Util.Padding import pad, unpad
import os

def runAES(dataSize):  # a function is defined to take in the data size (in bytes) to encrypt/decrypt
    def encryptAES(data, key):
        cipherObj = AES.new(key, AES.MODE_CBC)
        encrypted = cipherObj.encrypt(pad(data.encode(), AES.block_size))  # ensure plaintext size is a multiple of 16 (AES block size)
        return cipherObj.iv + encrypted

    def decryptAES(encryptedData, key):
        iv = encryptedData[:AES.block_size]     # extracts encrypted data
        encrypted = encryptedData[AES.block_size:]
        cipherObj = AES.new(key, AES.MODE_CBC, iv) # recreates cipher object with the same key & initialization vector
        decrypted = unpad(cipherObj.decrypt(encrypted), AES.block_size)
        return decrypted.decode()

    data = "X" * dataSize       # creates a string of simulated plaintext of specified size
    key = os.urandom(16)        # generates a random 16-byte key

    startTime = time.time()
    encryptedData = encryptAES(data, key)
    encryptionTime = time.time() - startTime
    if encryptionTime < 0.000001:   # avoids calculation error
        encryptionTime = 0.000001

    decryptionStartTime = time.time()
    decryptedData = decryptAES(encryptedData, key)
    decryptionTime = time.time() - decryptionStartTime

    def calcThroughput(dataSize, timeTaken):    # throughput calculation
        if timeTaken == 0:
            return 0        # avoids division by zero error
        return dataSize / timeTaken

    # throughput formula: (data size/time taken) in bytes per second (Bps)
    encryptionThroughput = calcThroughput(len(data), encryptionTime)
    decryptionThroughput = calcThroughput(len(data), decryptionTime)

    cpuUsage = psutil.cpu_percent(interval = 1)     # measures CPU usage over a 1-second interval

    print(f"----- RESULT: AES for {dataSize}B -----")
    print(f"Encryption Time: {encryptionTime:.6f} s")
    print(f"Decryption Time: {decryptionTime:.6f} s")
    print(f"Encryption Throughput: {encryptionThroughput:.4f} Bps")
    print(f"Decryption Throughput: {decryptionThroughput:.4f} Bps")
    print(f"CPU Usage During Encryption: {cpuUsage:.2f}%")

runAES(64)     # EXECUTION -- simulation conducted with 64 / 1024 / 16384 / 1048576 bytes