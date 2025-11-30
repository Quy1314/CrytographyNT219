from collections import Counter
import string

# Known English letter frequencies (from most frequent to least frequent)
english_frequencies = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

cipher_text = ("◔◆●□⊟ ◕◇⊟ ◓⊟◍⊟∆◔⊟ ◐⊠ ◕◇⊟ ⊠◆◓◔◕ ●◐✦⊟◍, ◇∆◓◓✪ ◑◐◕◕⊟◓ ∆●⊞ ◕◇⊟ ◑◇◆◍◐◔◐◑◇⊟◓'◔ ◔◕◐●⊟, ◐● 26 ◉★●⊟ 1997, ◕◇⊟ ⊡◐◐○◔ ◇∆✦⊟ ⊠◐★●⊞ ◆◎◎⊟●◔⊟ ◑◐◑★◍∆◓◆◕✪ ∆●⊞ □◐◎◎⊟◓□◆∆◍ ◔★□□⊟◔◔ ✧◐◓◍⊞✧◆⊞⊟. ◕◇⊟✪ ◇∆✦⊟ ∆◕◕◓∆□◕⊟⊞ ∆ ✧◆⊞⊟ ∆⊞★◍◕ ∆★⊞◆⊟●□⊟ ∆◔ ✧⊟◍◍ ∆◔ ✪◐★●◈⊟◓ ◓⊟∆⊞⊟◓◔ ∆●⊞ ∆◓⊟ ✧◆⊞⊟◍✪ □◐●◔◆⊞⊟◓⊟⊞ □◐◓●⊟◓◔◕◐●⊟◔ ◐⊠ ◎◐⊞⊟◓● ◍◆◕⊟◓∆◕★◓⊟,[3][4] ◕◇◐★◈◇ ◕◇⊟ ⊡◐◐○◔ ◇∆✦⊟ ◓⊟□⊟◆✦⊟⊞ ◎◆✩⊟⊞ ◓⊟✦◆⊟✧◔ ⊠◓◐◎ □◓◆◕◆□◔ ∆●⊞ ◍◆◕⊟◓∆◓✪ ◔□◇◐◍∆◓◔. ∆◔ ◐⊠ ⊠⊟⊡◓★∆◓✪ 2023, ◕◇⊟ ⊡◐◐○◔ ◇∆✦⊟ ◔◐◍⊞ ◎◐◓⊟ ◕◇∆● 600 ◎◆◍◍◆◐● □◐◑◆⊟◔ ✧◐◓◍⊞✧◆⊞⊟, ◎∆○◆●◈ ◕◇⊟◎ ◕◇⊟ ⊡⊟◔◕-◔⊟◍◍◆●◈ ⊡◐◐○ ◔⊟◓◆⊟◔ ◆● ◇◆◔◕◐◓✪, ∆✦∆◆◍∆⊡◍⊟ ◆● ⊞◐✫⊟●◔ ◐⊠ ◍∆●◈★∆◈⊟◔. ◕◇⊟ ◍∆◔◕ ⊠◐★◓ ⊡◐◐○◔ ∆◍◍ ◔⊟◕ ◓⊟□◐◓⊞◔ ∆◔ ◕◇⊟ ⊠∆◔◕⊟◔◕-◔⊟◍◍◆●◈ ⊡◐◐○◔ ◆● ◇◆◔◕◐◓✪, ✧◆◕◇ ◕◇⊟ ⊠◆●∆◍ ◆●◔◕∆◍◎⊟●◕ ◔⊟◍◍◆●◈ ◓◐★◈◇◍✪ 2.7 ◎◆◍◍◆◐● □◐◑◆⊟◔ ◆● ◕◇⊟ ★●◆◕⊟⊞ ○◆●◈⊞◐◎ ∆●⊞ 8.3 ◎◆◍◍◆◐● □◐◑◆⊟◔ ◆● ◕◇⊟ ★●◆◕⊟⊞ ◔◕∆◕⊟◔ ✧◆◕◇◆● ◕✧⊟●◕✪-⊠◐★◓ ◇◐★◓◔ ◐⊠ ◆◕◔ ◓⊟◍⊟∆◔⊟. ◆◕ ◇◐◍⊞◔ ◕◇⊟ ◈★◆●●⊟◔◔ ✧◐◓◍⊞ ◓⊟□◐◓⊞ ⊠◐◓ ⊡⊟◔◕-◔⊟◍◍◆●◈ ⊡◐◐○ ◔⊟◓◆⊟◔ ⊠◐◓ □◇◆◍⊞◓⊟●.")

def extract_cipher_symbols(text):
    symbols = set()
    for char in text:
        if char not in ' .,[]\'0123456789-':
            symbols.add(char)
    return symbols

# Get all unique cipher symbols
cipher_symbols = extract_cipher_symbols(cipher_text)
print("Unique cipher symbols found:")
print(sorted(cipher_symbols))
print(f"Total unique symbols: {len(cipher_symbols)}")

# Count frequencies of cipher symbols
cipher_symbol_text = ''.join(char for char in cipher_text if char in cipher_symbols)
cipher_counts = Counter(cipher_symbol_text)

# Sort the cipher symbols by frequency
sorted_cipher_symbols = [item[0] for item in cipher_counts.most_common()]

print("\nSymbol frequencies (most to least frequent):")
for symbol, count in cipher_counts.most_common():
    print(f"'{symbol}': {count}")

# Create mapping from cipher symbols to English letters based on frequency
mapping = {}
for i, symbol in enumerate(sorted_cipher_symbols):
    if i < len(english_frequencies):
        mapping[symbol] = english_frequencies[i]
    else:
        mapping[symbol] = chr(ord('A') + i)

# Optional manual adjustments to improve decryption quality
# mapping["◔"] = "H"
# mapping["◆"] = "E" 
# mapping["●"] = "L"
# mapping["◇"] = "L"
# mapping["⊟"] = "O"

def print_key_mapping_table(mapping):
    """
    Displays the key mapping in the requested table format:
          A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
     --+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
     ◔  ◆  ●  □  ⊟  ◕  ◇  ⊟  ◓  ⊟  ◍  ⊟  ∆  ◔  ⊟  ◐  ⊠  ◕  ◇  ⊟  ⊠  ◆  ◓  ◔  ◕
    """
    plain_letters = list(string.ascii_uppercase)
    row1 = " ".join(f"{letter:2}" for letter in plain_letters)
    row2 = " " + "--" + "+--"*(len(plain_letters)-1) + " "
    reverse_mapping = {v: k for k, v in mapping.items()}
    row3 = " ".join(f"{reverse_mapping.get(letter, '?'):2}" for letter in plain_letters)
         
    print("\nKey Mapping Table (Letter -> Symbol):")
    print(row1)
    print(row2)
    print(row3)

def decrypt_text(cipher_text, mapping):
    decrypted = []
    for char in cipher_text:
        if char in mapping:
            decrypted.append(mapping[char])
        else:
            decrypted.append(char)
    return ''.join(decrypted)

decrypted_text = decrypt_text(cipher_text, mapping)

print("\nInitial Decrypted Text (based on frequency analysis):")
print(decrypted_text)

# Final results
print("\n" + "="*60)
print("FINAL RESULTS")
print("="*60)

print_key_mapping_table(mapping)

final_decrypted_text = decrypt_text(cipher_text, mapping)
print("\nFinal Decrypted Text:")
print(final_decrypted_text)