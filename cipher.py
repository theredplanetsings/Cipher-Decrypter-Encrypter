import string
import os
"""
This program provides functionality for encrypting and decrypting text
using various classical ciphers, currently being the Caesar Cipher, Vigenère Cipher, and Rail Fence Cipher.

Usage:
    python3 cipher.py

Dependencies:
    None

Functions:
    shift_text(text, shift):
        Shifts each letter in the input text by the specified number of positions.

    count_frequencies(text):
        Returns a list of the letter frequencies in the input text.

    distance(freq1, freq2):
        Returns the distance between two frequency distributions.

    crack_cipher_from_text(cipher_text):
        Bruteforces the Caesar cipher from manually entered text.

    crack_cipher_from_file(file_name, action):
        Bruteforces the Caesar cipher from a text file. 'action' specifies whether to encrypt or decrypt.

    encrypt_text(text):
        Encrypts the input text using all possible Caesar cipher variations.

    encrypt_vigenere(text, key):
        Encrypts the input text using the Vigenère Cipher with the specified key.

    decrypt_vigenere(text, key):
        Decrypts the input text using the Vigenère Cipher with the specified key.

    encrypt_rail_fence(text, key):
        Encrypts the input text using the Rail Fence Cipher with the specified key.

    decrypt_rail_fence(text, key):
        Decrypts the input text using the Rail Fence Cipher with the specified key.

    select_cipher_type():
        Prompts the user to select the cipher type: Caesar Cipher, Vigenère Cipher, or Rail Fence Cipher.

    main():
        Executes the main functionality of the program:
        - Prompts the user to select the cipher type.
        - Decrypts or encrypts text based on user input, either from a file or manual input.

Example:
    Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: decrypt
    Enter 'file' to read from a file or 'text' to type the text manually: file
    Enter the name of the input file (Note: The file must be in the same directory as the Python file): encrypted_text.txt
    Decoded text (shift forward 1): ...
    Decoded text (shift forward 2): ...
    ...
"""
__author__ = "https://github.com/theredplanetsings"
__date__ = "30/03/2024"

ENGLISH_FREQ = [
    8.2, 1.5, 2.8, 4.3, 13.0, 2.2, 2.0, 6.1, 7.0, 0.2, 0.8, 4.0, 2.4,
    6.7, 7.5, 1.9, 0.1, 6.0, 6.3, 9.0, 2.8, 1.0, 2.4, 0.2, 2.0, 0.1
]

def shift_text(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            if ch.islower():
                base = ord('a')
            else:
                base = ord('A')
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch
    return result

def count_frequencies(text):
    freqs = [0] * 26
    num_letters = 0
    for ch in text:
        if ch.isalpha():
            freqs[ord(ch.lower()) - ord('a')] += 1
            num_letters += 1
    return [freq / num_letters * 100 for freq in freqs]

def distance(freq1, freq2):
    return sum(abs(f1 - f2) for f1, f2 in zip(freq1, freq2))

def get_unique_file_name(file_name):
    base_name, ext = os.path.splitext(file_name)
    counter = 0
    while True:
        new_file_name = f"{base_name}_{counter}{ext}"
        if not os.path.isfile(new_file_name):
            return new_file_name
        counter += 1

def crack_cipher_from_text(cipher_text):
    output = ""
    output += "Bruteforcing through all possible Caesar cipher variations...\n"
    for key in range(1, 26):
        decoded_text_forward = shift_text(cipher_text, key)
        output += f"Decoded text (shift forward {key}): {decoded_text_forward}\n"
    output += "\n" * 3
    for key in range(1, 26):
        decoded_text_backward = shift_text(cipher_text, -key)
        output += f"Decoded text (shift backward {key}): {decoded_text_backward}\n"
    return output

def crack_cipher_from_file(file_name, action):
    file_path = os.path.join(os.path.dirname(__file__), file_name)
    if os.path.isfile(file_path):
        with open(file_path, "r") as in_file:
            text = in_file.read()
        
        output = crack_cipher_from_text(text)
        
        if action.lower() == 'encrypt':
            unique_file_name = get_unique_file_name(file_name.replace(".txt", "_encrypted.txt"))
        elif action.lower() == 'decrypt':
            unique_file_name = get_unique_file_name(file_name.replace(".txt", "_decrypted.txt"))
        
        with open(unique_file_name, "a") as out_file:
            out_file.write(text + "\n\n")
            out_file.write(output)
        
        print(f"Output written to {unique_file_name}.")
    else:
        print("File not found.")

def encrypt_text(text):
    output = ""
    output += "Encrypting with all possible Caesar cipher variations...\n"
    for key in range(1, 26):
        encrypted_text_forward = shift_text(text, key)
        output += f"Encrypted text (shift forward {key}): {encrypted_text_forward}\n"
    output += "\n" * 1
    for key in range(1, 26):
        encrypted_text_backward = shift_text(text, -key)
        output += f"Encrypted text (shift backward {key}): {encrypted_text_backward}\n"
    return output

def encrypt_vigenere(text, key):
    encrypted_text = ""
    key_length = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_length].lower()) - ord('a')
            encrypted_char = shift_text(char, shift)
            encrypted_text += encrypted_char
            key_index += 1
        else:
            encrypted_text += char
    return encrypted_text

def decrypt_vigenere(text, key):
    decrypted_text = ""
    key_length = len(key)
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_length].lower()) - ord('a')
            decrypted_char = shift_text(char, -shift)
            decrypted_text += decrypted_char
            key_index += 1
        else:
            decrypted_text += char
    return decrypted_text

def encrypt_rail_fence(text, key):
    if key == 1:  # Edge case: if key is 1, return the original text
        return text
    
    # Encryption logic for Rail Fence Cipher
    # Initialize empty list to store rails
    rails = [[] for _ in range(key)]
    
    # Variables to keep track of the current rail and direction
    current_rail = 0
    going_down = False
    
    # Fill the rails
    for char in text:
        # Add the character to the current rail
        rails[current_rail].append(char)
        # Check if we need to change direction
        if current_rail == 0 or current_rail == key - 1:
            going_down = not going_down
        # Move to the next rail
        if going_down:
            current_rail += 1
        else:
            current_rail -= 1
    
    # Concatenate the rails to get the encrypted text
    encrypted_text = ''.join([''.join(rail) for rail in rails])
    return encrypted_text

def decrypt_rail_fence(text, key):
    # Decryption logic for Rail Fence Cipher
    # Initialize an empty grid to reconstruct the rails
    grid = [['' for _ in range(len(text))] for _ in range(key)]
    
    # Variables to keep track of the current rail and direction
    current_row = 0
    going_down = False
    
    # Fill the grid with placeholder characters to represent the rails
    for i in range(len(text)):
        grid[current_row][i] = '*'
        if current_row == 0 or current_row == key - 1:
            going_down = not going_down
        if going_down:
            current_row += 1
        else:
            current_row -= 1
    
    # Populate the grid with the characters from the encrypted text
    index = 0
    for i in range(key):
        for j in range(len(text)):
            if grid[i][j] == '*' and index < len(text):
                grid[i][j] = text[index]
                index += 1
    
    # Reconstruct the rails from the grid
    rail_indices = [[] for _ in range(key)]
    current_row = 0
    going_down = False
    for i in range(len(text)):
        rail_indices[current_row].append(i)
        if current_row == 0 or current_row == key - 1:
            going_down = not going_down
        if going_down:
            current_row += 1
        else:
            current_row -= 1

    # Construct the decrypted text from the rail indices
    decrypted_text = ''
    for i in range(len(text)):
        for row in range(key):
            if i in rail_indices[row]:
                decrypted_text += grid[row][i]

    return decrypted_text

def select_cipher_type():
    print("Select the cipher type:")
    print("1. Caesar Cipher")
    print("2. Vigenère Cipher")
    print("3. Rail Fence Cipher")
    choice = input("Enter the number corresponding to the cipher type: ")
    return choice

def main():
    cipher_choice = None

    while cipher_choice not in ['1', '2', '3']:
        print("Select the cipher type:")
        print("1. Caesar Cipher")
        print("2. Vigenère Cipher")
        print("3. Rail Fence Cipher")
        cipher_choice = input("Enter the number corresponding to the cipher type: ")

    if cipher_choice == '1':
        # Caesar Cipher
        action = input("Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: ")
        while action.lower() not in ['decrypt', 'encrypt']:
            print("Invalid choice. Please enter 'decrypt' or 'encrypt'.")
            action = input("Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: ")
        
        choice = input("Enter 'file' to read from a file or 'text' to type the text manually: ")
        while choice.lower() not in ['file', 'text']:
            print("Invalid choice. Please enter 'file' or 'text'.")
            choice = input("Enter 'file' to read from a file or 'text' to type the text manually: ")
        
        if choice.lower() == 'file':
            file_name = input("Enter the name of the input file (Note: The file must be in the same directory as the Python file): ")
            crack_cipher_from_file(file_name, action)

        elif choice.lower() == 'text':
            if action.lower() == 'decrypt':
                cipher_text = input("Enter the cipher text: ")
                output = crack_cipher_from_text(cipher_text)
                print(output)
                
            elif action.lower() == 'encrypt':
                plain_text = input("Enter the plain text: ")
                output = encrypt_text(plain_text)
                print(output)

    elif cipher_choice == '2':
        # Vigenère Cipher
        action = input("Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: ")
        while action.lower() not in ['decrypt', 'encrypt']:
            print("Invalid choice. Please enter 'decrypt' or 'encrypt'.")
            action = input("Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: ")
        
        choice = input("Enter 'file' to read from a file or 'text' to type the text manually: ")
        while choice.lower() not in ['file', 'text']:
            print("Invalid choice. Please enter 'file' or 'text'.")
            choice = input("Enter 'file' to read from a file or 'text' to type the text manually: ")
        
        if choice.lower() == 'file':
            file_name = input("Enter the name of the input file (Note: The file must be in the same directory as the Python file): ")
            key = input("Enter the encryption/decryption key: ")
            if action.lower() == 'decrypt':
                output_file_name = get_unique_file_name("vigenere_decrypted.txt")
                with open(file_name, "r") as in_file:
                    text = in_file.read()
                output = decrypt_vigenere(text, key)
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Key: {key}\n")
                    out_file.write(f"Cipher Text: {text}\n")
                    out_file.write(f"Decrypted Text: {output}\n")
                print(f"Decrypted text written to {output_file_name}.")
            elif action.lower() == 'encrypt':
                output_file_name = get_unique_file_name("vigenere_encrypted.txt")
                with open(file_name, "r") as in_file:
                    text = in_file.read()
                output = encrypt_vigenere(text, key)
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Key: {key}\n")
                    out_file.write(f"Plain Text: {text}\n")
                    out_file.write(f"Encrypted Text: {output}\n")
                print(f"Encrypted text written to {output_file_name}.")
                
        elif choice.lower() == 'text':
            key = input("Enter the encryption/decryption key: ")
            if action.lower() == 'decrypt':
                cipher_text = input("Enter the cipher text: ")
                output = decrypt_vigenere(cipher_text, key)
                output_file_name = get_unique_file_name("vigenere_decrypted.txt")
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Key: {key}\n")
                    out_file.write(f"Cipher Text: {cipher_text}\n")
                    out_file.write(f"Decrypted Text: {output}\n")
                print(f"Decrypted text written to {output_file_name}.")
            elif action.lower() == 'encrypt':
                plain_text = input("Enter the plain text: ")
                output = encrypt_vigenere(plain_text, key)
                output_file_name = get_unique_file_name("vigenere_encrypted.txt")
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Key: {key}\n")
                    out_file.write(f"Plain Text: {plain_text}\n")
                    out_file.write(f"Encrypted Text: {output}\n")
                print(f"Encrypted text written to {output_file_name}.")

    elif cipher_choice == '3':
        # Rail Fence Cipher
        action = input("Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: ")
        while action.lower() not in ['decrypt', 'encrypt']:
            print("Invalid choice. Please enter 'decrypt' or 'encrypt'.")
            action = input("Enter 'decrypt' to decrypt a message or 'encrypt' to encrypt a message: ")
        
        choice = input("Enter 'file' to read from a file or 'text' to type the text manually: ")
        while choice.lower() not in ['file', 'text']:
            print("Invalid choice. Please enter 'file' or 'text'.")
            choice = input("Enter 'file' to read from a file or 'text' to type the text manually: ")
        
        key = None
        while not isinstance(key, int):
            try:
                key = int(input("Enter the Rail Fence key: "))
                if key <= 0:
                    print("Key must be a positive integer.")
                    key = None
            except ValueError:
                print("Invalid key. Please enter a valid integer.")
        
        if choice.lower() == 'file':
            file_name = input("Enter the name of the input file (Note: The file must be in the same directory as the Python file): ")
            file_extension = file_name.split('.')[-1]
            if action.lower() == 'decrypt':
                with open(file_name, "r") as in_file:
                    text = in_file.read()
                decrypted_text = decrypt_rail_fence(text, key)
                output_file_name = f"rail_fence_decrypted_key_{key}.{file_extension}"
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Key: {key}\n")
                    out_file.write(f"Cipher Text: {text}\n")
                    out_file.write(f"Decrypted Text: {decrypted_text}\n")
                print(f"Decrypted text for key {key} written to {output_file_name}.")
            elif action.lower() == 'encrypt':
                with open(file_name, "r") as in_file:
                    text = in_file.read()
                encrypted_text = encrypt_rail_fence(text, key)
                output_file_name = f"rail_fence_encrypted_key_{key}.{file_extension}"
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Key: {key}\n")
                    out_file.write(f"Plain Text: {text}\n")
                    out_file.write(f"Encrypted Text: {encrypted_text}\n")
                print(f"Encrypted text for key {key} written to {output_file_name}.")

        elif choice.lower() == 'text':
            if action.lower() == 'decrypt':
                cipher_text = input("Enter the cipher text: ")
                decrypted_text = decrypt_rail_fence(cipher_text, key)
                print(f"Decrypted text for key {key}: {decrypted_text}")
            elif action.lower() == 'encrypt':
                plain_text = input("Enter the plain text: ")
                encrypted_text = encrypt_rail_fence(plain_text, key)
                print(f"Encrypted text for key {key}: {encrypted_text}")

if __name__ == "__main__":
    main()
