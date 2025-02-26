from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# AES encryption
def encrypt_data(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return cipher.iv + encrypted_data  # Return IV + encrypted data for decryption

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_data.decode('utf-8')

# LSB encoding
def encode_image(image_path, secret_data, output_path, key):
    image = Image.open(image_path)
    binary_data = ''.join(format(byte, '08b') for byte in encrypt_data(secret_data, key))  # Encrypt and convert to binary
    
    # Check if the image can hold the data
    if len(binary_data) > image.width * image.height * 3:
        raise ValueError("Image is too small to hide the data.")

    data_index = 0
    pixels = image.load()
    
    # Modify the image pixel by pixel
    for y in range(image.height):
        for x in range(image.width):
            pixel = list(pixels[x, y])
            for i in range(3):  # For R, G, B channels
                if data_index < len(binary_data):
                    pixel[i] = pixel[i] & ~1 | int(binary_data[data_index])
                    data_index += 1
            pixels[x, y] = tuple(pixel)

    image.save(output_path)
    print("Data hidden successfully!")

# LSB decoding
def decode_image(image_path, key):
    image = Image.open(image_path)
    binary_data = ""
    pixels = image.load()

    # Extract the least significant bit from each pixel
    for y in range(image.height):
        for x in range(image.width):
            pixel = pixels[x, y]
            for i in range(3):  # For R, G, B channels
                binary_data += str(pixel[i] & 1)
    
    # Convert binary data back to encrypted data
    encrypted_data = bytearray()
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        encrypted_data.append(int(byte, 2))
    
    # Decrypt and return the message
    return decrypt_data(bytes(encrypted_data), key)

# Example usage
image_path = 'input_image.png'
output_path = 'output_image.png'
secret_message = "This is a secret message"
key = 'mysecretkey12345'

# Encode the message in the image
encode_image(image_path, secret_message, output_path, key)

# Decode the message from the image
extracted_message = decode_image(output_path, key)
print("Extracted message:", extracted_message)