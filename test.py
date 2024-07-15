from Crypto.Cipher import AES
import base64

ENCRYPTION_KEY = "5c6ca91bfff2ee1530ffbea36e746011"

def decrypt_message(encrypted_message):
    try:
        # Decode the base64 encoded string
        encrypted_message = base64.b64decode(encrypted_message)
        # Extract the IV
        iv = encrypted_message[:16]
        cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_CBC, iv)
        # Decrypt the message
        decrypted_message = cipher.decrypt(encrypted_message[16:])
        # Remove padding
        padding_length = decrypted_message[-1]
        decrypted_message = decrypted_message[:-padding_length]
        return decrypted_message.decode("utf-8")
    except Exception as e:
        return str(e)

# Example usage:
def decrypt_and_print(encrypted_data):
    decrypted_data = decrypt_message(encrypted_data)
    print("Decrypted Data:", decrypted_data)
    return decrypted_data

# Example encrypted data (base64 encoded AES encrypted data)
encrypted_data = "U2FsdGVkX191G89bjQGmZJwZHJ+oEeGkf7wIQVKKmwcV4nh0ParyKSRVOhYy9+k6T4UXVf2ZRFhznA2v9KOv3CQjmAfftRoAnUtMjlJKRonMNuaJwv4LVxCW/UGS9rpjOzBIT/Nsr76XgW2fPd4URA=="
decrypted_data = decrypt_and_print(encrypted_data)
