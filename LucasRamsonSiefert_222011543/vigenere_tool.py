# Vigenère Cipher
# Encrypter, Decrypter and Key-Finder.
# Lucas Ramson Siefert - 222011543
import string

alphabet = string.ascii_lowercase
LETTERS = string.ascii_uppercase
freq = {
    'en': [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.2, 0.8, 4.0, 2.4, 6.8, 7.5, 1.9, 0.1, 6.0, 6.3, 9.1, 2.8,
           1.0, 2.4, 0.2, 2.0, 0.1],
    'pt': [14.6, 1.0, 3.9, 4.9, 12.5, 1.0, 1.3, 1.2, 6.2, 0.4, 0.0, 2.8, 4.7, 5.0, 10.7, 2.5, 1.2, 6.5, 7.8, 4.3,
           4.6, 1.7, 0.0, 0.5, 0.0, 0.5]
}


# encrypts the message with the given key
def encrypt(message, key):
    i = 0  # keystream index
    decrypted_message = ''

    # generates a keystream based on the "clean" message, which is the message without punctuation or accents
    clean_message = ''.join(list(filter(lambda x: x.isalpha() and x.lower() in alphabet, message))).strip()
    keystream = ''.join([key[i % len(key)] for i in range(len(clean_message))])

    for character in message:
        # keep non letter characters intact and don't increment the keystream index
        if character not in alphabet:
            decrypted_message += character
            continue
        # shifts the ASCII value of the character based on the current letter's alphabet index
        decrypted_message += chr((ord(character) - 97 + string.ascii_lowercase.index(keystream[i])) % 26 + 97)
        i += 1

    return decrypted_message


# decrypts the message with the given key
def decrypt(message, key):
    i = 0  # keystream index
    decrypted_message = ''

    # generates a keystream based on the "clean" message, which is the message without punctuation or accents
    clean_message = ''.join(list(filter(lambda x: x.isalpha() and x.lower() in alphabet, message))).strip()
    keystream = ''.join([key[i % len(key)] for i in range(len(clean_message))])

    for character in message:
        # keep non letter characters intact and don't increment the keystream index
        if character not in alphabet:
            decrypted_message += character
            continue
        # shifts the ASCII value of the character based on the current letter's alphabet index
        decrypted_message += chr((ord(character) - 97 - string.ascii_lowercase.index(keystream[i])) % 26 + 97)
        i += 1

    return decrypted_message


# returns an expected key length for the ciphered text
def kasiski_examination(ciphertext, max_key, tolerance):

    # initialize and fill a list with the amount of characters between repeated groups of 3 characters
    spaces = []
    for i in range(len(ciphertext) - 2):
        tmp = ciphertext[i:i+3]
        for j in range(3, len(ciphertext) - 2 - i):
            if tmp == ciphertext[i+j:i+j+3]:
                spaces.append(j)
                break

    # we don't want our key to be bigger than the message, right?
    if max_key > len(ciphertext):
        max_key = len(ciphertext)

    # calculate the most common divisor in the spaces list
    max_gdc = 0
    key_len = 0
    for i in range(2, max_key + 1):
        counter = 0
        for n in spaces:
            if n % i == 0:
                counter += 1
        # the tolerance sum here makes it easier for higher key_len values to be assigned.
        # for instance, if the key_len is 8, than 4 and 2 will have an initially larger counter, but with the tolerance
        # we can compensate for that, as it's usually more probable that the key will be larger and, if not, it's
        # counter should be high enough for the tolerance to not matter.
        if counter + tolerance > max_gdc:
            key_len = i
            max_gdc = counter

    return key_len


# performs an analysis on letter frequency with different keys and returns the most probable key
def frequency_analysis(ciphertext, key_length, language):
    # group ciphertext into columns according to key length
    columns = ['' for _ in range(key_length)]
    for i, character in enumerate(ciphertext):
        columns[i % key_length] += character

    # analyze frequency of each column and guess key letter
    key = ''
    for column in columns:
        best_shift = 0
        min_diff = float('inf')
        # tests each shift value up to the alphabet's length.
        # essentially what this is doing is decrypting every column with every letter in the alphabet. The letter that
        # yields the least frequency difference from the expected language letter frequency gets chosen
        for shift in range(len(LETTERS)):
            shifted_column = ''
            for character in column:
                shifted_column += LETTERS[(LETTERS.index(character) - shift) % len(LETTERS)]
            freq_column = [100 * shifted_column.count(letter) / len(shifted_column) for letter in LETTERS]
            diff = sum((f - freq[language][i]) ** 2 for i, f in enumerate(freq_column))
            if diff < min_diff:
                min_diff = diff
                best_shift = shift
        key += LETTERS[best_shift]
    return key


# executes the attack on the cipher, returns the most probable key.
def attack(ciphertext, language, max_key=20, tolerance=10):
    key_len = kasiski_examination(ciphertext, max_key, tolerance)

    print("\nEstimated key length:", key_len)
    key = frequency_analysis(ciphertext.upper(), key_len, language)
    print("Most probable key:", key)

    return key


# UI
opt = int(input("(1) - Encrypt\n(2) - Decrypt\n(3) - Key Finder\n"))

message = input('Enter the text:\n')
multiline = [message]
# multiline input handler. finishes with empty line
while True:
    text = input()
    if text.strip() == "":
        break
    multiline.append(text)
message = ' '.join(multiline)

if (opt == 1) or (opt == 2):
    key = input('Enter the key:\n').lower()
    if opt == 1:
        print(encrypt(message, key))
    else:
        print(decrypt(message, key))

elif opt == 3:
    language = str(input('Choose a language:\n (en) - English\n (pt) - Portuguese\n'))
    if (language == 'pt') or (language == 'en'):
        clean_message = ''.join(list(filter(lambda x: x.isalpha() and x.lower() in alphabet, message))).strip()
        guessed_key = attack(clean_message, language)
        print_decipher = str(input('Would you like to decipher the message with the predicted key? (y/n)'))
        if print_decipher == 'y':
            print(decrypt(message, guessed_key.lower()))
