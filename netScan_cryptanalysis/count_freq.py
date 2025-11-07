#!/usr/bin/env python3
"""
Frequency analysis tool for breaking substitution ciphers
"""

# Format: 'ciphertext_letter': 'PLAINTEXT_LETTER'
SUBSTITUTION_MAP = {
    'u': 'S',
    'h': 'E',
    'k': 'C',
    'w': 'U',
    'f': 'R',
    'r': 'I',
    'y': 'T',
    'p': 'Y',
    'b': 'G',
    't': 'N',
    'c': 'A',
    'n': 'B',
    'j': 'O',
    'a': 'L',
    'q': 'M',
    'l': 'H',
    'd': 'P',
    'x': 'F',
    's': 'V',
    'v': 'X',
    'i': 'D',
    'g': 'W',
    'm': 'Z',
    'z': 'Q',
    'e': 'K',
    'o': 'J',
}

print(sorted(SUBSTITUTION_MAP.items()))

def count_frequencies(text):
    """Count the frequency of each letter in the text"""
    
    # Count only lowercase letters a-z
    letter_counts = {}
    total_letters = 0
    
    for char in text:
        if char.islower() and char.isalpha():
            letter_counts[char] = letter_counts.get(char, 0) + 1
            total_letters += 1
    
    # Sort by frequency 
    sorted_letters = sorted(letter_counts.items(), key=lambda x: x[1], reverse=True)
    
    return sorted_letters, total_letters


def display_frequencies(sorted_letters, total_letters):
    """Display frequency analysis"""
    print(f"Total letters analyzed: {total_letters}\n")
    print("Character Frequencies (sorted by count):")
    print("-" * 50)
    print(f"{'Letter':<10} {'Count':<10} {'Percentage':<10}")
    print("-" * 50)
    
    for letter, count in sorted_letters:
        percentage = (count / total_letters) * 100
        print(f"{letter:<10} {count:<10} {percentage:>6.2f}%")
    
    print("\n" + "=" * 50)

def apply_substitution(text, sub_map):
    """Apply the substitution mapping to the text"""
    result = []
    for char in text:
        if char in sub_map:
            result.append(sub_map[char])
        else:
            result.append(char)
    return ''.join(result)


def main():
    filename = 'cipher.txt'  
    
    # Read the file
    try:
        with open(filename, 'r') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print(f"Error: Could not find '{filename}'")
        print("Make sure the file is in the same directory as this script.")
        return
    
    # Show frequency analysis
    sorted_letters, total_letters = count_frequencies(ciphertext)
    display_frequencies(sorted_letters, total_letters)
    
    # Apply substitution with the above map
    if SUBSTITUTION_MAP:
        print("Applying substitutions:")
        for cipher, plain in SUBSTITUTION_MAP.items():
            print(f"  {cipher} -> {plain}")
        print("\n" + "=" * 70)
        print("DECRYPTED TEXT:")
        print("=" * 70)
        
        decrypted = apply_substitution(ciphertext, SUBSTITUTION_MAP)
        print(decrypted)
    else:
        print("No substitutions defined yet.")
        print("Edit the SUBSTITUTION_MAP dictionary at the top of this file.")
        print("\nExample:")
        print("  SUBSTITUTION_MAP = {")
        print("      'h': 'E',")
        print("      'y': 'T',")
        print("  }")


if __name__ == "__main__":
    main()