from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes





KEY = b'ThisIsA16ByteKey'  



def encrypt_file(data):

    cipher = AES.new(KEY, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce + tag + ciphertext



def decrypt_file(encrypted_data):

    nonce = encrypted_data[:16]

    tag = encrypted_data[16:32]

    ciphertext = encrypted_data[32:]

    cipher = AES.new(KEY, AES.MODE_EAX, nonce)

    return cipher.decrypt_and_verify(ciphertext, tag)
