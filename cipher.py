import string
import os
"""
This program provides functionality to bruteforce Caesar ciphers, 
and it encrypts/decrypts using the Vigenère Cipher with a given key.

Both can be used to decode text either from a file or by manual input.

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

    crack_vigenere(cipher_text, max_key_length=50):
        Bruteforces the Vigenère cipher with a maximum key length (default is 50).

    select_cipher_type():
        Prompts the user to select the cipher type: Caesar Cipher or Vigenère Cipher.

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

def crack_vigenere(cipher_text, max_key_length=50):
    output = ""
    output += "Bruteforcing through all possible Vigenère cipher variations...\n"
    for key_length in range(1, min(max_key_length, len(cipher_text)) + 1):
        output += f"Trying key length: {key_length}\n"
        for key_index in range(key_length):
            possible_key = ""
            for i in range(key_index, len(cipher_text), key_length):
                possible_key += cipher_text[i]
            output += f"  Subkey at index {key_index}: {possible_key}\n"
    return output

def select_cipher_type():
    print("Select the cipher type:")
    print("1. Caesar Cipher")
    print("2. Vigenère Cipher")
    choice = input("Enter the number corresponding to the cipher type: ")
    return choice

def main():
    cipher_choice = select_cipher_type()

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
            if action.lower() == 'decrypt' and key.lower() == 'none':
                output_file_name = "vigenere_bruteforce_decrypted.txt"
                with open(file_name, "r") as in_file:
                    text = in_file.read()
                output = crack_vigenere(text)
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Vigenere Bruteforce Decryption Result:\n{output}\n")
                print(f"Bruteforce decryption result written to {output_file_name}.")
            elif action.lower() == 'decrypt':
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
            if action.lower() == 'decrypt' and key.lower() == 'none':
                cipher_text = input("Enter the cipher text: ")
                output = crack_vigenere(cipher_text)
                output_file_name = get_unique_file_name("vigenere_bruteforce_decrypted.txt")
                with open(output_file_name, "w") as out_file:
                    out_file.write(f"Vigenere Bruteforce Decryption Result:\n{output}\n")
                print(f"Bruteforce decryption result written to {output_file_name}.")
            elif action.lower() == 'decrypt':
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
    else:
        print("Invalid choice.")
        
if __name__ == "__main__":
    main()
