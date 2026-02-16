import sys
from quantaweave import QuantaWeave

def main():
    print("QuantaWeave CLI Test1")
    print("1. Generate keypair")
    print("2. Encrypt message")
    print("3. Decrypt message")
    print("4. Exit")
    pqc = QuantaWeave(security_level='LEVEL1')
    public_key, private_key = None, None
    ciphertext = None
    while True:
        choice = input("Select option: ")
        if choice == '1':
            public_key, private_key = pqc.generate_keypair()
            print("Public key:", public_key)
            print("Private key:", private_key)
        elif choice == '2':
            if not public_key:
                print("Generate a keypair first.")
                continue
            msg = input("Enter message to encrypt: ").encode('utf-8')
            ciphertext = pqc.encrypt(msg, public_key)
            print("Ciphertext:", ciphertext)
        elif choice == '3':
            if not private_key or not ciphertext:
                print("Generate keypair and encrypt a message first.")
                continue
            plaintext = pqc.decrypt(ciphertext, private_key)
            print("Decrypted message:", plaintext.decode('utf-8', errors='replace'))
        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
