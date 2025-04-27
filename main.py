"""
Program Utama Mini-AES
Fitur:
1. Enkripsi/Dekripsi 16-bit (single block)
2. Mode Operasi ECB dan CBC untuk data >16-bit
3. Tampilan proses tiap round
4. Support input teks/hex/file
"""

from encrypt_decrypt import MiniAESCorePurePython
import argparse
import sys

# ---- Konstanta Mode Operasi ----
MODE_ECB = "ECB"
MODE_CBC = "CBC"
DEFAULT_IV = 0xFFFF  # Initialization Vector untuk CBC

# ---- Inisialisasi Core Mini-AES ----
mini_aes = MiniAESCorePurePython()

# ---- Fungsi Bantuan ----
def split_into_blocks(data_hex, block_size=4):
    """Membagi string hex menjadi blok-blok 16-bit (4 karakter hex)."""
    return [data_hex[i:i+block_size] for i in range(0, len(data_hex), block_size)]

def pad_hex_string(hex_str, block_size=4):
    """Padding string hex agar panjangnya kelipatan block_size."""
    padding_length = (block_size - len(hex_str) % block_size) % block_size
    return hex_str + '0' * padding_length

def text_to_hex(text):
    """Konversi teks ke string hex."""
    return ''.join(f"{ord(c):02X}" for c in text)

def hex_to_text(hex_str):
    """Konversi string hex ke teks."""
    try:
        return bytes.fromhex(hex_str).decode()
    except:
        return hex_str

def hex_to_state(hex_str):
    """Konversi hex string ke state format."""
    return [int(c, 16) for c in hex_str]

def state_to_hex(state):
    """Konversi state ke hex string."""
    return ''.join(f'{nibble:X}' for nibble in state)

# ---- Mode Operasi ----
def encrypt_ecb(plaintext_hex, key_hex, verbose=False):
    """Enkripsi dalam mode ECB."""
    blocks = split_into_blocks(pad_hex_string(plaintext_hex))
    ciphertext = []
    key_state = hex_to_state(key_hex)
    
    for block in blocks:
        block_state = hex_to_state(block)
        cipher_state = mini_aes.encrypt(block_state, key_state, verbose=verbose)
        ciphertext.append(state_to_hex(cipher_state))
    
    return ''.join(ciphertext)

def decrypt_ecb(ciphertext_hex, key_hex, verbose=False):
    """Dekripsi dalam mode ECB."""
    blocks = split_into_blocks(ciphertext_hex)
    plaintext = []
    key_state = hex_to_state(key_hex)
    
    for block in blocks:
        block_state = hex_to_state(block)
        plain_state = mini_aes.decrypt(block_state, key_state, verbose=verbose)
        plaintext.append(state_to_hex(plain_state))
    
    return ''.join(plaintext)

def encrypt_cbc(plaintext_hex, key_hex, iv=DEFAULT_IV, verbose=False):
    """Enkripsi dalam mode CBC."""
    blocks = split_into_blocks(pad_hex_string(plaintext_hex))
    ciphertext = []
    prev_block = hex_to_state(f"{iv:04X}")
    key_state = hex_to_state(key_hex)
    
    for block in blocks:
        block_state = hex_to_state(block)
        # XOR dengan blok sebelumnya
        xor_block = [block_state[i] ^ prev_block[i] for i in range(4)]
        cipher_state = mini_aes.encrypt(xor_block, key_state, verbose=verbose)
        ciphertext.append(state_to_hex(cipher_state))
        prev_block = cipher_state
    
    return ''.join(ciphertext)

def decrypt_cbc(ciphertext_hex, key_hex, iv=DEFAULT_IV, verbose=False):
    """Dekripsi dalam mode CBC."""
    blocks = split_into_blocks(ciphertext_hex)
    plaintext = []
    prev_block = hex_to_state(f"{iv:04X}")
    key_state = hex_to_state(key_hex)
    
    for block in blocks:
        block_state = hex_to_state(block)
        plain_state = mini_aes.decrypt(block_state, key_state, verbose=verbose)
        # XOR dengan blok ciphertext sebelumnya
        xor_block = [plain_state[i] ^ prev_block[i] for i in range(4)]
        plaintext.append(state_to_hex(xor_block))
        prev_block = block_state
    
    return ''.join(plaintext)

# ---- Fungsi Utama ----
def process_file(input_file, output_file, key, mode, action, verbose=False):
    """Proses enkripsi/dekripsi file."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read().hex()
        
        if action == 'encrypt':
            if mode == MODE_ECB:
                result = encrypt_ecb(data, key, verbose)
            else:
                result = encrypt_cbc(data, key, verbose=verbose)
        else:
            if mode == MODE_ECB:
                result = decrypt_ecb(data, key, verbose)
            else:
                result = decrypt_cbc(data, key, verbose=verbose)
        
        with open(output_file, 'wb') as f:
            f.write(bytes.fromhex(result))
        
        print(f"File {action}ed successfully! Output saved to {output_file}")
    except Exception as e:
        print(f"Error processing file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Mini-AES Encryption/Decryption Tool")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('input', help="Input (text, hex string, or file)")
    parser.add_argument('key', help="Encryption key (16-bit hex, e.g., A73B)")
    parser.add_argument('-m', '--mode', choices=[MODE_ECB, MODE_CBC], default=MODE_ECB, help="Block cipher mode")
    parser.add_argument('-f', '--file', action='store_true', help="Treat input as file")
    parser.add_argument('-o', '--output', help="Output file path")
    parser.add_argument('-v', '--verbose', action='store_true', help="Show round details")
    
    args = parser.parse_args()

    try:
        # Validasi key
        if len(args.key) != 4:
            raise ValueError("Key must be 4-character hex string (16-bit)")
        int(args.key, 16)  # Validasi hex

        if args.file:
            if not args.output:
                print("Error: Output file path required when processing files")
                sys.exit(1)
            process_file(args.input, args.output, args.key, args.mode, args.action, args.verbose)
        else:
            # Check if input is hex
            is_hex = False
            try:
                # Try to validate if it's a hex string
                if all(c in '0123456789ABCDEFabcdef' for c in args.input):
                    int(args.input, 16)
                    input_hex = args.input
                    is_hex = True
                else:
                    input_hex = text_to_hex(args.input)
            except ValueError:
                input_hex = text_to_hex(args.input)

            # Pad input if needed
            if len(input_hex) % 4 != 0:
                input_hex = pad_hex_string(input_hex)

            if args.action == 'encrypt':
                if args.mode == MODE_ECB:
                    result = encrypt_ecb(input_hex, args.key, args.verbose)
                else:
                    result = encrypt_cbc(input_hex, args.key, verbose=args.verbose)
            else:
                if args.mode == MODE_ECB:
                    result = decrypt_ecb(input_hex, args.key, args.verbose)
                else:
                    result = decrypt_cbc(input_hex, args.key, verbose=args.verbose)

            # Output result
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(result)
                print(f"Result saved to {args.output}")
            else:
                print(f"\nResult ({args.mode} {args.action}):")
                print(f"Hex: {result}")
                if not is_hex:
                    try:
                        text_result = hex_to_text(result)
                        print(f"Text: {result}")
                    except:
                        pass

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()