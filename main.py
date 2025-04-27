"""
Program Utama Mini-AES
Fitur:
1. Enkripsi/Dekripsi 16-bit (single block)
2. Mode Operasi ECB dan CBC untuk data >16-bit
3. Tampilan proses tiap round
4. Support input teks/hex/file
5. Uji Avalanche Effect (sensitivitas perubahan 1-bit pada plaintext/key) # Added Feature
"""

from encrypt_decrypt import MiniAESCorePurePython
import argparse
import sys
import random # Diimpor untuk memilih bit acak pada uji avalanche

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
        # Coba decode dengan utf-8, ganti karakter error jika ada
        return bytes.fromhex(hex_str).decode('utf-8', errors='replace')
    except ValueError:
        # Jika hex tidak valid, kembalikan string asli
        return hex_str
    except Exception:
         # Tangkap error lain saat decode
         return hex_str

def hex_to_state(hex_str):
    """Konversi hex string ke state format."""
    # Gunakan fungsi dari kelas MiniAES
    return mini_aes.hex_to_state(hex_str)

def state_to_hex(state):
    """Konversi state ke hex string."""
    # Gunakan fungsi dari kelas MiniAES
    return mini_aes.state_to_hex(state)

# ---- Mode Operasi ----
def encrypt_ecb(plaintext_hex, key_hex, verbose=False):
    """Enkripsi dalam mode ECB."""
    # Pastikan input di-pad
    padded_plaintext = pad_hex_string(plaintext_hex)
    blocks = split_into_blocks(padded_plaintext)
    ciphertext = []
    key_state = hex_to_state(key_hex)

    if verbose and len(blocks) > 1: print("\nMemproses Blok ECB (Enkripsi):")
    for i, block in enumerate(blocks):
        if verbose and len(blocks) > 1: print(f"\n--- Blok {i+1} ({block}) ---")
        block_state = hex_to_state(block)
        cipher_state = mini_aes.encrypt(block_state, key_state, verbose=verbose)
        ciphertext.append(state_to_hex(cipher_state))

    return ''.join(ciphertext)

def decrypt_ecb(ciphertext_hex, key_hex, verbose=False):
    """Dekripsi dalam mode ECB."""
    # Periksa panjang ciphertext, idealnya kelipatan 4
    if len(ciphertext_hex) % 4 != 0:
        print("Peringatan: Panjang ciphertext tidak kelipatan 4. Hasil mungkin tidak akurat.")
    blocks = split_into_blocks(ciphertext_hex)
    plaintext = []
    key_state = hex_to_state(key_hex)

    if verbose and len(blocks) > 1: print("\nMemproses Blok ECB (Dekripsi):")
    for i, block in enumerate(blocks):
        if verbose and len(blocks) > 1: print(f"\n--- Blok {i+1} ({block}) ---")
        block_state = hex_to_state(block)
        plain_state = mini_aes.decrypt(block_state, key_state, verbose=verbose)
        plaintext.append(state_to_hex(plain_state))

    return ''.join(plaintext)

def encrypt_cbc(plaintext_hex, key_hex, iv=DEFAULT_IV, verbose=False):
    """Enkripsi dalam mode CBC."""
    # Pastikan input di-pad
    padded_plaintext = pad_hex_string(plaintext_hex)
    blocks = split_into_blocks(padded_plaintext)
    ciphertext = []
    # Konversi IV ke state
    prev_block_state = hex_to_state(f"{iv:04X}")
    key_state = hex_to_state(key_hex)

    if verbose: print(f"\nMenggunakan IV: {iv:04X}")
    if verbose and len(blocks) > 1: print("\nMemproses Blok CBC (Enkripsi):")
    for i, block in enumerate(blocks):
        if verbose and len(blocks) > 1: print(f"\n--- Blok {i+1} ({block}) ---")
        block_state = hex_to_state(block)
        # XOR dengan blok sebelumnya (atau IV)
        if verbose and len(blocks) > 1: print(f"   XOR dengan Prev CT/IV ({state_to_hex(prev_block_state)})")
        xor_block_state = [block_state[j] ^ prev_block_state[j] for j in range(4)]
        if verbose and len(blocks) > 1: print(f"   -> Hasil XOR: {state_to_hex(xor_block_state)}")

        # Enkripsi hasil XOR
        cipher_state = mini_aes.encrypt(xor_block_state, key_state, verbose=verbose)
        ciphertext.append(state_to_hex(cipher_state))
        # Simpan state ciphertext saat ini untuk blok berikutnya
        prev_block_state = cipher_state

    return ''.join(ciphertext)

def decrypt_cbc(ciphertext_hex, key_hex, iv=DEFAULT_IV, verbose=False):
    """Dekripsi dalam mode CBC."""
    # Periksa panjang ciphertext
    if len(ciphertext_hex) % 4 != 0:
        print("Peringatan: Panjang ciphertext tidak kelipatan 4. Hasil mungkin tidak akurat.")
    blocks = split_into_blocks(ciphertext_hex)
    plaintext = []
    # Konversi IV ke state
    prev_block_state = hex_to_state(f"{iv:04X}")
    key_state = hex_to_state(key_hex)

    if verbose: print(f"\nMenggunakan IV: {iv:04X}")
    if verbose and len(blocks) > 1: print("\nMemproses Blok CBC (Dekripsi):")
    for i, block in enumerate(blocks):
        current_block_state = hex_to_state(block) # Simpan state ciphertext blok ini
        if verbose and len(blocks) > 1: print(f"\n--- Blok {i+1} ({block}) ---")

        # Dekripsi blok ciphertext saat ini
        decrypted_state = mini_aes.decrypt(current_block_state, key_state, verbose=verbose)

        # XOR hasil dekripsi dengan blok ciphertext sebelumnya (atau IV)
        if verbose and len(blocks) > 1: print(f"   XOR dengan Prev CT/IV ({state_to_hex(prev_block_state)})")
        xor_block_state = [decrypted_state[j] ^ prev_block_state[j] for j in range(4)]
        plaintext.append(state_to_hex(xor_block_state))
        if verbose and len(blocks) > 1: print(f"   -> Hasil Plaintext Blok: {state_to_hex(xor_block_state)}")

        # Update blok sebelumnya untuk iterasi berikutnya
        prev_block_state = current_block_state

    return ''.join(plaintext)

# ---- Fungsi untuk Uji Avalanche Effect ---- (Bagian Baru)
def hamming_distance(hex_str1, hex_str2):
    """Menghitung Hamming Distance (jumlah bit yang berbeda) antara dua hex string."""
    # Pastikan panjang sama
    if len(hex_str1) != len(hex_str2):
        raise ValueError("String hex harus memiliki panjang yang sama untuk Hamming distance.")
    # Konversi hex ke integer
    val1 = int(hex_str1, 16)
    val2 = int(hex_str2, 16)
    # Operasi XOR akan menghasilkan bit 1 di posisi yang berbeda
    xor_val = val1 ^ val2
    # Hitung jumlah bit 1 (set bits) dalam hasil XOR
    distance = 0
    while xor_val > 0:
        distance += xor_val & 1 # Cek bit terakhir
        xor_val >>= 1         # Geser ke kanan
    return distance

def test_avalanche_effect(plaintext_hex, key_hex):
    """Menjalankan tes Avalanche Effect untuk Mini-AES (1 blok)."""
    # Validasi input spesifik untuk tes ini
    if len(plaintext_hex) != 4 or len(key_hex) != 4:
        print("Error: Tes Avalanche memerlukan tepat satu blok 16-bit (4 karakter hex) untuk plaintext dan kunci.")
        return

    print("\n--- Uji Avalanche Effect ---")
    # 0. Enkripsi original sebagai basis perbandingan
    pt_state_orig = hex_to_state(plaintext_hex)
    key_state_orig = hex_to_state(key_hex)
    try:
        # Enkripsi tanpa verbose internal agar output tes lebih bersih
        original_ct_state = mini_aes.encrypt(pt_state_orig, key_state_orig, verbose=False)
        original_ct_hex = state_to_hex(original_ct_state)
        print(f"Original PT: {plaintext_hex}, Key: {key_hex} -> CT: {original_ct_hex}")
    except Exception as e:
        print(f"Error saat enkripsi original untuk tes: {e}")
        return # Tidak bisa melanjutkan tes jika enkripsi awal gagal

    total_bits = 16 # Jumlah bit dalam satu blok

    # 1. Uji Sensitivitas Plaintext: Ubah 1 bit acak pada plaintext
    try:
        print(f"\n1. Mengubah 1 bit acak pada Plaintext ({plaintext_hex}):")
        # Pilih posisi bit yang akan diubah (0 sampai 15)
        bit_pos_pt = random.randint(0, total_bits - 1)
        pt_int = int(plaintext_hex, 16)
        # Balik bit pada posisi terpilih menggunakan XOR dan bitmask
        flipped_pt_int = pt_int ^ (1 << bit_pos_pt)
        # Format kembali ke hex 4 karakter (dengan padding '0' jika perlu)
        flipped_pt_hex = f"{flipped_pt_int:04X}"
        flipped_pt_state = hex_to_state(flipped_pt_hex)

        # Enkripsi plaintext yang sudah diubah
        flipped_pt_ct_state = mini_aes.encrypt(flipped_pt_state, key_state_orig, verbose=False)
        flipped_pt_ct_hex = state_to_hex(flipped_pt_ct_state)
        # Hitung perbedaan bit antara ciphertext asli dan yang baru
        pt_diff = hamming_distance(original_ct_hex, flipped_pt_ct_hex)
        pt_diff_percent = (pt_diff / total_bits) * 100

        print(f"   Bit ke-{bit_pos_pt} diubah -> Plaintext Baru: {flipped_pt_hex}")
        print(f"   Ciphertext Hasil                     : {flipped_pt_ct_hex}")
        print(f"   -> Jarak Hamming vs Original CT      : {pt_diff} bit ({pt_diff_percent:.2f}%)")
    except Exception as e:
        print(f"   Error saat uji sensitivitas plaintext: {e}")

    # 2. Uji Sensitivitas Kunci: Ubah 1 bit acak pada kunci
    try:
        print(f"\n2. Mengubah 1 bit acak pada Kunci ({key_hex}):")
        # Pilih posisi bit yang akan diubah
        bit_pos_key = random.randint(0, total_bits - 1)
        key_int = int(key_hex, 16)
        # Balik bit kunci
        flipped_key_int = key_int ^ (1 << bit_pos_key)
        flipped_key_hex = f"{flipped_key_int:04X}"
        flipped_key_state = hex_to_state(flipped_key_hex)

        # Enkripsi plaintext *ASLI* dengan kunci yang sudah diubah
        flipped_key_ct_state = mini_aes.encrypt(pt_state_orig, flipped_key_state, verbose=False)
        flipped_key_ct_hex = state_to_hex(flipped_key_ct_state)
        # Hitung perbedaan bit
        key_diff = hamming_distance(original_ct_hex, flipped_key_ct_hex)
        key_diff_percent = (key_diff / total_bits) * 100

        print(f"   Bit ke-{bit_pos_key} diubah -> Kunci Baru    : {flipped_key_hex}")
        print(f"   Ciphertext Hasil                     : {flipped_key_ct_hex}")
        print(f"   -> Jarak Hamming vs Original CT      : {key_diff} bit ({key_diff_percent:.2f}%)")
    except Exception as e:
        print(f"   Error saat uji sensitivitas kunci: {e}")

    print(f"\n*Catatan: Avalanche effect yang baik idealnya menghasilkan perubahan sekitar 50% bit ({total_bits // 2} bit).")
    print("--- Akhir Uji Avalanche Effect ---")


# ---- Fungsi Utama ----
def process_file(input_file, output_file, key_hex, mode, action, iv=DEFAULT_IV, verbose=False):
    """Proses enkripsi/dekripsi file."""
    try:
        # Baca file sebagai bytes, lalu konversi ke hex string
        with open(input_file, 'rb') as f:
            data_hex = f.read().hex()
        print(f"Membaca file '{input_file}' ({len(data_hex)//2} bytes).")

        result_hex = ""
        if action == 'encrypt':
            if mode == MODE_ECB:
                result_hex = encrypt_ecb(data_hex, key_hex, verbose)
            else: # MODE_CBC
                result_hex = encrypt_cbc(data_hex, key_hex, iv, verbose)
        else: # action == 'decrypt'
            if mode == MODE_ECB:
                result_hex = decrypt_ecb(data_hex, key_hex, verbose)
            else: # MODE_CBC
                result_hex = decrypt_cbc(data_hex, key_hex, iv, verbose)

        # Tulis hasil (dalam bentuk bytes) ke file output
        with open(output_file, 'wb') as f:
            f.write(bytes.fromhex(result_hex)) # Konversi hex ke bytes

        print(f"File berhasil di-{action}! Output disimpan ke {output_file}")

    except FileNotFoundError:
         print(f"Error: File input '{input_file}' tidak ditemukan.")
         sys.exit(1)
    except Exception as e:
        print(f"Error saat memproses file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Mini-AES Encryption/Decryption Tool")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('input', help="Input (text, hex string, or file)")
    parser.add_argument('key', help="Encryption key (16-bit hex, e.g., A73B)")
    parser.add_argument('-m', '--mode', choices=[MODE_ECB, MODE_CBC], default=MODE_ECB, help="Block cipher mode")
    # Tambahkan argumen IV untuk CBC
    parser.add_argument('--iv', help="Initialization Vector (IV) hex 4-karakter untuk CBC (default: FFFF)", default=f"{DEFAULT_IV:04X}")
    parser.add_argument('-f', '--file', action='store_true', help="Treat input as file")
    parser.add_argument('-o', '--output', help="Output file path")
    parser.add_argument('-v', '--verbose', action='store_true', help="Show round details")
    # Tambahkan argumen untuk tes avalanche
    parser.add_argument('--avalanche', action='store_true', help="Jalankan tes avalanche effect (input & kunci harus hex 4-karakter)")

    args = parser.parse_args()

    # --- Cek jika ingin menjalankan tes Avalanche --- (Bagian Baru)
    if args.avalanche:
        if args.file:
            print("Error: Tes Avalanche tidak bisa digunakan dengan input file (-f).")
            sys.exit(1)
        try:
            # Validasi khusus untuk avalanche: input dan key HARUS hex 4 karakter
            if not (len(args.input) == 4 and all(c in '0123456789ABCDEFabcdef' for c in args.input)):
                 raise ValueError("Input untuk tes avalanche harus berupa string hex 4 karakter.")
            if not (len(args.key) == 4 and all(c in '0123456789ABCDEFabcdef' for c in args.key)):
                 raise ValueError("Kunci untuk tes avalanche harus berupa string hex 4 karakter.")
            # Coba konversi untuk memastikan format benar
            int(args.input, 16)
            int(args.key, 16)

            # Panggil fungsi tes dan keluar dari program
            test_avalanche_effect(args.input.upper(), args.key.upper())
            sys.exit(0) # Berhenti setelah tes selesai
        except ValueError as e:
            print(f"Error validasi input/kunci untuk tes avalanche: {e}")
            sys.exit(1)
        except Exception as e:
             print(f"Error tak terduga saat persiapan tes avalanche: {e}")
             sys.exit(1)
    # --- Akhir Cek Avalanche ---

    # --- Proses Enkripsi/Dekripsi Normal ---
    try:
        # Validasi key
        if len(args.key) != 4:
            raise ValueError("Key must be 4-character hex string (16-bit)")
        key_hex = args.key.upper() # Gunakan uppercase
        int(key_hex, 16)  # Validasi hex

        # Validasi IV jika mode CBC
        iv_int = DEFAULT_IV
        if args.mode == MODE_CBC:
             try:
                 if len(args.iv) != 4:
                      raise ValueError("IV must be a 4-character hex string (16-bit).")
                 iv_int = int(args.iv, 16)
                 # Pastikan IV dalam range 16-bit
                 if not (0 <= iv_int <= 0xFFFF):
                      raise ValueError("IV hex value must be between 0000 and FFFF.")
             except ValueError as e:
                  print(f"Error: Invalid IV provided - {e}")
                  sys.exit(1)

        # Proses file atau string
        if args.file:
            if not args.output:
                print("Error: Output file path (-o) required when processing files (-f)")
                sys.exit(1)
            process_file(args.input, args.output, key_hex, args.mode, args.action, iv_int, args.verbose)
        else:
            # Handle input string (teks atau hex)
            input_data = args.input
            is_input_hex = False
            input_hex = ""

            # Coba deteksi apakah input adalah hex
            try:
                # Kondisi: semua char adalah hex dan panjang genap (untuk byte utuh)
                if all(c in '0123456789ABCDEFabcdef' for c in input_data) and len(input_data) % 2 == 0:
                    int(input_data, 16) # Tes konversi
                    input_hex = input_data.upper()
                    is_input_hex = True
                    print("Input terdeteksi sebagai HEX.")
                else:
                    input_hex = text_to_hex(input_data)
                    print(f"Input teks dikonversi ke HEX: {input_hex}")
            except ValueError:
                 # Jika gagal deteksi/konversi hex, anggap sebagai teks
                 input_hex = text_to_hex(input_data)
                 print(f"Input (gagal deteksi hex) dianggap teks, dikonversi ke HEX: {input_hex}")

            # Padding tidak diperlukan lagi di sini karena fungsi encrypt/decrypt sudah handle

            # Jalankan enkripsi/dekripsi
            result_hex = ""
            if args.action == 'encrypt':
                if args.mode == MODE_ECB:
                    result_hex = encrypt_ecb(input_hex, key_hex, args.verbose)
                else: # CBC
                    result_hex = encrypt_cbc(input_hex, key_hex, iv_int, args.verbose)
            else: # decrypt
                if args.mode == MODE_ECB:
                    result_hex = decrypt_ecb(input_hex, key_hex, args.verbose)
                else: # CBC
                    result_hex = decrypt_cbc(input_hex, key_hex, iv_int, args.verbose)

            # Tampilkan atau simpan hasil
            print(f"\n--- Hasil ({args.mode} {args.action}) ---")
            print(f"Hex : {result_hex}")

            # Coba konversi hasil ke teks jika memungkinkan/diinginkan
            # Terutama berguna saat dekripsi, atau jika input awal adalah teks
            try_decode = (args.action == 'decrypt') or (not is_input_hex)
            if try_decode:
                 try:
                     text_result = hex_to_text(result_hex)
                     # Tampilkan teks jika berbeda dari hex & terlihat seperti teks
                     # (cek karakter printable ASCII atau whitespace umum)
                     is_printable = all(32 <= ord(c) < 127 or ord(c) in [9, 10, 13] for c in text_result)
                     if text_result != result_hex and is_printable and text_result:
                          print(f"Teks: {text_result}")
                     # Jika hasil dekripsi adalah hex kosong (misal dari padding 00)
                     elif args.action == 'decrypt' and not text_result and result_hex == '00'* (len(result_hex)//2):
                          print("(Hasil dekripsi kemungkinan adalah byte NUL dari padding)")

                 except Exception:
                      # Jika gagal decode, tidak apa-apa, hex sudah ditampilkan
                      pass # Tidak perlu print error di sini

            # Simpan hasil ke file jika diminta
            if args.output:
                try:
                    # Tulis hasil hex string ke file
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(result_hex)
                    print(f"\nHasil hex disimpan ke {args.output}")
                except IOError as e:
                     print(f"\nError: Gagal menulis ke file output '{args.output}': {e}")

    except ValueError as e: # Tangkap error validasi (misal format kunci salah)
        print(f"Error Validasi: {e}")
        sys.exit(1)
    except Exception as e: # Tangkap error umum lainnya
        print(f"Error: Terjadi kesalahan - {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()