import copy

# --- Aritmetika GF(2^4) (Modulo x^4 + x + 1) ---
# Polinomial irreduksi x^4 + x + 1 direpresentasikan sebagai biner 10011
IRREDUCIBLE_POLY = 0b10011

def gf_add(a, b):
  """Penjumlahan dalam GF(2^4) adalah operasi XOR."""
  return a ^ b

def gf_multiply(a, b):
    """Perkalian dalam GF(2^4) menggunakan algoritma 'peasant's' dengan reduksi."""
    p = 0  # Inisialisasi hasil
    for _ in range(4): # Ulangi 4 kali untuk 4 bit
        if b & 1:  # Jika bit terendah dari b adalah 1
            p ^= a # Tambahkan a ke hasil (menggunakan XOR)
        # Periksa apakah bit tertinggi (most significant bit, bit ke-3) dari a diset
        msb_set = a & 0b1000
        a <<= 1 # Geser kiri a (sama dengan mengalikan dengan x)
        if msb_set:
            # Jika MSB diset, kurangi dengan polinomial irreduksi (menggunakan XOR)
            a ^= IRREDUCIBLE_POLY
        # Pastikan a tetap dalam 4 bit (masking) agar tetap di GF(16)
        a &= 0b1111
        b >>= 1 # Geser kanan b
    return p

# --- Kelas Inti MiniAES ---
class MiniAESCorePurePython:
    """
    Mengimplementasikan inti Mini-AES 16-bit berdasarkan paper Phan (Cryptologia 2002).
    Termasuk jadwal kunci (key schedule) dan dekripsi dasar.
    """
    def __init__(self):
        self._key_size = 16 # Ukuran kunci dalam bit
        # S-Box (Tabel 1 dalam paper Phan) - untuk substitusi
        self._sboxE = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
        # Inverse S-Box (Tabel 3 dalam paper Phan) - untuk dekripsi
        self._sboxD = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5]
        # Matriks MixColumns [[3, 2], [2, 3]] (dari Gambar 5)
        self._mc_matrix = [[3, 2], [2, 3]]
        # Konstanta Putaran (Round Constants) (Bagian 3.6)
        # RCON[0] tidak digunakan, RCON[1]=1 (0001), RCON[2]=2 (0010)
        self._RCON = [0, 1, 2]

    def __repr__(self):
        """Representasi string dari kelas."""
        return "Mini-AES Core Pure Python (Spesifikasi Phan)"

    # --- Fungsi Bantuan Representasi Data ---
    def hex_to_state(self, hex_string):
        """Mengonversi 4 karakter hex (s00 s10 s01 s11) ke list state [s00, s10, s01, s11]."""
        if len(hex_string) != 4:
            raise ValueError("String hex input harus terdiri dari 4 karakter.")
        try:
            # Konversi setiap karakter hex ke integer (nibble)
            state = [int(c, 16) for c in hex_string]
            if len(state) != 4:
                raise ValueError("Konversi menghasilkan panjang state yang salah.")
            return state
        except ValueError:
            raise ValueError("Ditemukan karakter heksadesimal yang tidak valid.")

    def state_to_hex(self, state):
        """Mengonversi list state [s00, s10, s01, s11] ke string hex 4 karakter."""
        if not isinstance(state, list) or len(state) != 4:
            raise TypeError("Input state harus berupa list dari 4 integer (nibble).")
        # Format setiap nibble sebagai karakter hex tunggal dan gabungkan
        return "".join(f'{nibble:X}' for nibble in state)

    # --- Operasi Inti AES ---
    def sub_nibbles(self, state):
        """Melakukan operasi SubNibbles menggunakan S-Box."""
        # Ganti setiap nibble di state dengan nilai yang sesuai dari S-Box
        return [self._sboxE[nibble] for nibble in state]

    def shift_rows(self, state):
        """Melakukan operasi ShiftRows pada list state."""
        # State direpresentasikan sebagai [s00, s10, s01, s11]
        # Dalam matriks 2x2:
        # [s00 s01]
        # [s10 s11]
        # ShiftRows menukar elemen pada baris kedua: s10 <-> s11
        s00, s10, s01, s11 = state
        return [s00, s11, s01, s10] # State baru setelah pertukaran

    def mix_columns(self, state):
        """Melakukan operasi MixColumns menggunakan matriks konstan dan matematika GF(2^4)."""
        # State: [s00, s10, s01, s11]
        # Matriks: [[m00, m01], [m10, m11]] = [[3, 2], [2, 3]]
        s00, s10, s01, s11 = state
        m = self._mc_matrix
        # Kolom 0 baru:
        # d00 = (m00 * s00) + (m01 * s10)  <- perkalian & penjumlahan di GF(2^4)
        # d10 = (m10 * s00) + (m11 * s10)
        d00 = gf_add(gf_multiply(m[0][0], s00), gf_multiply(m[0][1], s10))
        d10 = gf_add(gf_multiply(m[1][0], s00), gf_multiply(m[1][1], s10))
        # Kolom 1 baru:
        # d01 = (m00 * s01) + (m01 * s11)
        # d11 = (m10 * s01) + (m11 * s11)
        d01 = gf_add(gf_multiply(m[0][0], s01), gf_multiply(m[0][1], s11))
        d11 = gf_add(gf_multiply(m[1][0], s01), gf_multiply(m[1][1], s11))
        # Kembalikan state baru [d00, d10, d01, d11]
        return [d00, d10, d01, d11]

    def add_round_key(self, state, round_key):
        """Melakukan operasi AddRoundKey (XOR per elemen)."""
        # XOR setiap nibble state dengan nibble round key yang bersesuaian
        return [gf_add(state[i], round_key[i]) for i in range(4)]

    # --- Ekspansi Kunci (Key Expansion) (Tabel 2 dalam paper Phan) ---
    def expand_key(self, key_state):
        """Menghasilkan kunci putaran K0, K1, K2 dari kunci utama."""
        # Inisialisasi list untuk menyimpan K0, K1, K2
        round_keys = [[0]*4 for _ in range(3)]
        # Array untuk menyimpan 'word' w0 hingga w11 (setiap word 1 nibble di Mini-AES)
        w = [0] * 12

        # K0 adalah kunci utama itu sendiri (w0, w1, w2, w3)
        round_keys[0] = list(key_state) # Salin K0
        w[0], w[1], w[2], w[3] = key_state[0], key_state[1], key_state[2], key_state[3]

        # Hitung word untuk K1 (w4, w5, w6, w7)
        temp_sub_w3 = self._sboxE[w[3]] # Lakukan NibbleSub(w3)
        # w4 = w0 XOR Sub(w3) XOR RCON[1]
        w[4] = gf_add(gf_add(w[0], temp_sub_w3), self._RCON[1])
        # w5 = w1 XOR w4
        w[5] = gf_add(w[1], w[4])
        # w6 = w2 XOR w5
        w[6] = gf_add(w[2], w[5])
        # w7 = w3 XOR w6
        w[7] = gf_add(w[3], w[6])
        round_keys[1] = [w[4], w[5], w[6], w[7]] # Simpan K1

        # Hitung word untuk K2 (w8, w9, w10, w11)
        temp_sub_w7 = self._sboxE[w[7]] # Lakukan NibbleSub(w7)
        # w8 = w4 XOR Sub(w7) XOR RCON[2]
        w[8] = gf_add(gf_add(w[4], temp_sub_w7), self._RCON[2])
        # w9 = w5 XOR w8
        w[9] = gf_add(w[5], w[8])
        # w10 = w6 XOR w9
        w[10] = gf_add(w[6], w[9])
        # w11 = w7 XOR w10
        w[11] = gf_add(w[7], w[10])
        round_keys[2] = [w[8], w[9], w[10], w[11]] # Simpan K2

        return round_keys # Kembalikan list berisi [K0, K1, K2]

    # --- Proses Enkripsi Utama ---
    def encrypt(self, plaintext_state, key_state, verbose=True):
        """Melakukan enkripsi Mini-AES."""
        # Dapatkan kunci putaran K0, K1, K2
        K0, K1, K2 = self.expand_key(key_state)
        if verbose:
            print(f"Kunci yang Dihitung:")
            print(f"  K0: {self.state_to_hex(K0)} -> {K0}")
            print(f"  K1: {self.state_to_hex(K1)} -> {K1}")
            print(f"  K2: {self.state_to_hex(K2)} -> {K2}\n")

        # AddRoundKey Awal (dengan K0)
        state = self.add_round_key(plaintext_state, K0)
        if verbose: print(f"Mulai    (AddK0): {self.state_to_hex(state)} -> {state}")

        # Putaran 1
        state = self.sub_nibbles(state)
        if verbose: print(f"Putaran 1 SubNib: {self.state_to_hex(state)} -> {state}")
        state = self.shift_rows(state)
        if verbose: print(f"Putaran 1 ShiftR: {self.state_to_hex(state)} -> {state}")
        state = self.mix_columns(state)
        if verbose: print(f"Putaran 1 MixCol: {self.state_to_hex(state)} -> {state}")
        state = self.add_round_key(state, K1) # AddRoundKey dengan K1
        if verbose: print(f"Putaran 1 AddK1:  {self.state_to_hex(state)} -> {state}")

        # Putaran 2 (Final)
        state = self.sub_nibbles(state)
        if verbose: print(f"Putaran 2 SubNib: {self.state_to_hex(state)} -> {state}")
        state = self.shift_rows(state)
        if verbose: print(f"Putaran 2 ShiftR: {self.state_to_hex(state)} -> {state}")
        # Tidak ada MixColumns pada putaran terakhir
        state = self.add_round_key(state, K2) # AddRoundKey dengan K2
        if verbose: print(f"Putaran 2 AddK2:  {self.state_to_hex(state)} -> {state}")

        return state # Kembalikan state ciphertext

    # --- Operasi Invers AES (untuk Dekripsi) ---
    def inv_sub_nibbles(self, state):
        """Melakukan operasi SubNibbles invers menggunakan Inverse S-Box."""
        # Ganti setiap nibble dengan nilai dari Inverse S-Box
        return [self._sboxD[nibble] for nibble in state]

    def inv_shift_rows(self, state):
        """Melakukan operasi ShiftRows invers (sama dengan ShiftRows untuk matriks 2x2)."""
        # Untuk matriks 2x2, ShiftRows adalah inversnya sendiri
        return self.shift_rows(state)

    def inv_mix_columns(self, state):
        """Melakukan operasi MixColumns invers."""
        # Untuk matriks spesifik [[3, 2], [2, 3]], matriks ini adalah inversnya sendiri
        # dalam GF(2^4). Jika matriks berbeda digunakan, inversnya diperlukan di sini.
        return self.mix_columns(state)

    # --- Proses Dekripsi Utama ---
    def decrypt(self, ciphertext_state, key_state, verbose=True):
        """Melakukan dekripsi Mini-AES."""
        # Dapatkan kunci putaran K0, K1, K2
        K0, K1, K2 = self.expand_key(key_state)
        if verbose:
            print(f"Menggunakan Kunci untuk Dekripsi:")
            print(f"  K0: {self.state_to_hex(K0)}")
            print(f"  K1: {self.state_to_hex(K1)}")
            print(f"  K2: {self.state_to_hex(K2)}\n")

        # Mulai dengan membatalkan AddRoundKey terakhir (K2)
        state = self.add_round_key(ciphertext_state, K2)
        if verbose: print(f"Mulai Dek (AddK2): {self.state_to_hex(state)}")

        # Putaran 2 Invers (Putaran Final Invers)
        state = self.inv_shift_rows(state) # Batalkan ShiftRows
        if verbose: print(f"Inv Ptr 2 ShiftR: {self.state_to_hex(state)}")
        state = self.inv_sub_nibbles(state) # Batalkan SubNibbles
        if verbose: print(f"Inv Ptr 2 SubNib: {self.state_to_hex(state)}")

        # Putaran 1 Invers
        state = self.add_round_key(state, K1) # Batalkan AddRoundKey K1
        if verbose: print(f"Inv Ptr 1 AddK1:  {self.state_to_hex(state)}")
        state = self.inv_mix_columns(state)   # Batalkan MixColumns
        if verbose: print(f"Inv Ptr 1 MixCol: {self.state_to_hex(state)}")
        state = self.inv_shift_rows(state)    # Batalkan ShiftRows
        if verbose: print(f"Inv Ptr 1 ShiftR: {self.state_to_hex(state)}")
        state = self.inv_sub_nibbles(state)   # Batalkan SubNibbles
        if verbose: print(f"Inv Ptr 1 SubNib: {self.state_to_hex(state)}")

        # AddRoundKey K0 Final (Membatalkan AddRoundKey Awal)
        state = self.add_round_key(state, K0)
        if verbose: print(f"Final Dek (AddK0): {self.state_to_hex(state)}")

        return state # Kembalikan state plaintext

# =================================
# Blok eksekusi utama untuk pengujian
# =================================
if __name__ == "__main__":
    # Contoh penggunaan langsung (jika file ini dijalankan)
    mini_aes = MiniAESCorePurePython()

    # Contoh data dari paper atau pengujian
    pt_hex_p = "9C63"  # Plaintext contoh (dalam hex)
    key_hex_p = "C3F0" # Kunci contoh (dalam hex)

    print(f"Plaintext : {pt_hex_p}")
    print(f"Kunci     : {key_hex_p}\n")

    # Konversi hex ke format state (list of nibbles)
    pt_state_p = mini_aes.hex_to_state(pt_hex_p)
    key_state_p = mini_aes.hex_to_state(key_hex_p)

    print("--- Enkripsi ---")
    # Lakukan enkripsi
    ct_state_p = mini_aes.encrypt(pt_state_p, key_state_p, verbose=True) # Set verbose=True untuk detail
    # Konversi state ciphertext kembali ke hex
    ct_hex_p_calc = mini_aes.state_to_hex(ct_state_p)
    print("-----------------------------")
    print(f"Ciphertext Hasil Hitung: {ct_hex_p_calc}")

    print("\n--- Dekripsi ---")
    # Lakukan dekripsi
    dec_state_p = mini_aes.decrypt(ct_state_p, key_state_p, verbose=True) # Set verbose=True untuk detail
    # Konversi state hasil dekripsi kembali ke hex
    dec_hex_p_calc = mini_aes.state_to_hex(dec_state_p)
    print("-----------------------------")
    print(f"Ciphertext Terdekripsi : {dec_hex_p_calc}")
    print(f"Plaintext Asli         : {pt_hex_p}")

    # Verifikasi apakah hasil dekripsi sama dengan plaintext asli
    if dec_hex_p_calc == pt_hex_p:
         print("VERIFIKASI DEKRIPSI: BERHASIL\n")
    else:
         print("VERIFIKASI DEKRIPSI: GAGAL\n")



# Plaintext : 9C63
# Kunci     : C3F0

# --- Enkripsi ---
# Kunci yang Dihitung:
#   K0: C3F0 -> [12, 3, 15, 0]
#   K1: 30FF -> [3, 0, 15, 15]
#   K2: 6696 -> [6, 6, 9, 6]

# Mulai    (AddK0): 5F93 -> [5, 15, 9, 3]
# Putaran 1 SubNib: F7A1 -> [15, 7, 10, 1]
# Putaran 1 ShiftR: F1A7 -> [15, 1, 10, 7]
# Putaran 1 MixCol: 0E3E -> [0, 14, 3, 14]
# Putaran 1 AddK1:  3EC1 -> [3, 14, 12, 1]
# Putaran 2 SubNib: 1054 -> [1, 0, 5, 4]
# Putaran 2 ShiftR: 1450 -> [1, 4, 5, 0]
# Putaran 2 AddK2:  72C6 -> [7, 2, 12, 6]
# -----------------------------
# Ciphertext Hasil Hitung: 72C6

# --- Dekripsi ---
# Menggunakan Kunci untuk Dekripsi:
#   K0: C3F0
#   K1: 30FF
#   K2: 6696

# Mulai Dek (AddK2): 1450
# Inv Ptr 2 ShiftR: 1054
# Inv Ptr 2 SubNib: 3EC1
# Inv Ptr 1 AddK1:  0E3E
# Inv Ptr 1 MixCol: F1A7
# Inv Ptr 1 ShiftR: F7A1
# Inv Ptr 1 SubNib: 5F93
# Final Dek (AddK0): 9C63
# -----------------------------
# Ciphertext Terdekripsi : 9C63
# Plaintext Asli         : 9C63
# VERIFIKASI DEKRIPSI: BERHASIL