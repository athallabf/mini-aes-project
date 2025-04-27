import copy

# --- GF(2^4) Arithmetic (Modulo x^4 + x + 1) ---
IRREDUCIBLE_POLY = 0b10011 # Represents x^4 + x + 1

def gf_add(a, b):
  """Addition in GF(2^4) is XOR."""
  return a ^ b

def gf_multiply(a, b):
    """Multiplication in GF(2^4) using peasant's algorithm with reduction."""
    p = 0
    for _ in range(4):
        if b & 1: # If the lowest bit of b is 1
            p ^= a # Add a to the result (XOR)
        msb_set = a & 0b1000 # Check if the highest bit (bit 3) of a is set
        a <<= 1 # Left shift a (multiply by x)
        if msb_set:
            a ^= IRREDUCIBLE_POLY # Reduce by XORing with the irreducible polynomial if needed
        a &= 0b1111 # Mask to 4 bits (keep within GF(16))
        b >>= 1 # Right shift b
    return p

# --- MiniAES Core Class ---
class MiniAESCorePurePython:
    """
    Implements Mini-AES 16-bit core based on Phan's paper (Cryptologia 2002).
    Includes key schedule and basic decryption.
    """
    def __init__(self):
        self._key_size = 16
        # S-Box (Table 1 in Phan's paper)
        self._sboxE = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
        # Inverse S-Box (Table 3 in Phan's paper)
        self._sboxD = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5]
        # MixColumns Matrix [[3, 2], [2, 3]] (from Figure 5)
        self._mc_matrix = [[3, 2], [2, 3]]
        # Round Constants (Section 3.6)
        self._RCON = [0, 1, 2] # RCON[1]=1 (0001), RCON[2]=2 (0010)

    def __repr__(self):
        return "Mini-AES Core Pure Python (Phan's Spec)"

    # --- Data Representation Helpers ---
    def hex_to_state(self, hex_string):
        """Converts 4-char hex (s00 s10 s01 s11) to state list [s00, s10, s01, s11]."""
        if len(hex_string) != 4: raise ValueError("Input hex string must be 4 characters long.")
        try:
            state = [int(c, 16) for c in hex_string]
            if len(state) != 4: raise ValueError("Conversion resulted in incorrect state length")
            return state
        except ValueError: raise ValueError("Invalid hexadecimal character found.")

    def state_to_hex(self, state):
        """Converts state list [s00, s10, s01, s11] to 4-char hex string."""
        if len(state) != 4: raise TypeError("Input state must be a list of 4 integers (nibbles).")
        return "".join(f'{nibble:X}' for nibble in state)

    # --- Core AES Operations ---
    def sub_nibbles(self, state):
        """Performs SubNibbles using the S-Box."""
        return [self._sboxE[nibble] for nibble in state]

    def shift_rows(self, state):
        """Performs ShiftRows on the state list."""
        s00, s10, s01, s11 = state
        # Swaps s10 and s11
        return [s00, s11, s01, s10]

    def mix_columns(self, state):
        """Performs MixColumns using the constant matrix and GF(2^4) math."""
        s00, s10, s01, s11 = state
        m = self._mc_matrix
        d00 = gf_add(gf_multiply(m[0][0], s00), gf_multiply(m[0][1], s10))
        d10 = gf_add(gf_multiply(m[1][0], s00), gf_multiply(m[1][1], s10))
        d01 = gf_add(gf_multiply(m[0][0], s01), gf_multiply(m[0][1], s11))
        d11 = gf_add(gf_multiply(m[1][0], s01), gf_multiply(m[1][1], s11))
        return [d00, d10, d01, d11]

    def add_round_key(self, state, round_key):
        """Performs AddRoundKey (element-wise XOR)."""
        return [gf_add(state[i], round_key[i]) for i in range(4)]

    # --- Key Expansion (Table 2 in Phan's paper) ---
    def expand_key(self, key_state):
        """Generates round keys K0, K1, K2 from the master key."""
        round_keys = [[0]*4 for _ in range(3)] # List for K0, K1, K2
        w = [0] * 12 # Array to hold words w0 to w11

        # K0 is the master key itself (w0, w1, w2, w3)
        round_keys[0] = list(key_state) # Copy K0
        w[0], w[1], w[2], w[3] = key_state[0], key_state[1], key_state[2], key_state[3]

        # Calculate K1 words (w4, w5, w6, w7)
        temp_sub_w3 = self._sboxE[w[3]] # NibbleSub(w3)
        w[4] = gf_add(gf_add(w[0], temp_sub_w3), self._RCON[1]) # w0 ^ Sub(w3) ^ RCON1
        w[5] = gf_add(w[1], w[4]) # w1 ^ w4
        w[6] = gf_add(w[2], w[5]) # w2 ^ w5
        w[7] = gf_add(w[3], w[6]) # w3 ^ w6
        round_keys[1] = [w[4], w[5], w[6], w[7]]

        # Calculate K2 words (w8, w9, w10, w11)
        temp_sub_w7 = self._sboxE[w[7]] # NibbleSub(w7)
        w[8] = gf_add(gf_add(w[4], temp_sub_w7), self._RCON[2]) # w4 ^ Sub(w7) ^ RCON2
        w[9] = gf_add(w[5], w[8]) # w5 ^ w8
        w[10] = gf_add(w[6], w[9]) # w6 ^ w9
        w[11] = gf_add(w[7], w[10]) # w7 ^ w10
        round_keys[2] = [w[8], w[9], w[10], w[11]]

        return round_keys

    # --- Main Encryption Process ---
    def encrypt(self, plaintext_state, key_state, verbose=True):
        """Performs Mini-AES encryption."""
        K0, K1, K2 = self.expand_key(key_state)
        if verbose:
            print(f"Calculated Keys:")
            print(f"  K0: {self.state_to_hex(K0)} -> {K0}")
            print(f"  K1: {self.state_to_hex(K1)} -> {K1}")
            print(f"  K2: {self.state_to_hex(K2)} -> {K2}\n")

        # Initial AddRoundKey
        state = self.add_round_key(plaintext_state, K0)
        if verbose: print(f"Start    (AddK0): {self.state_to_hex(state)} -> {state}")

        # Round 1
        state = self.sub_nibbles(state)
        if verbose: print(f"Round 1 SubNib: {self.state_to_hex(state)} -> {state}")
        state = self.shift_rows(state)
        if verbose: print(f"Round 1 ShiftR: {self.state_to_hex(state)} -> {state}")
        state = self.mix_columns(state)
        if verbose: print(f"Round 1 MixCol: {self.state_to_hex(state)} -> {state}")
        state = self.add_round_key(state, K1)
        if verbose: print(f"Round 1 AddK1:  {self.state_to_hex(state)} -> {state}")

        # Round 2 (Final)
        state = self.sub_nibbles(state)
        if verbose: print(f"Round 2 SubNib: {self.state_to_hex(state)} -> {state}")
        state = self.shift_rows(state)
        if verbose: print(f"Round 2 ShiftR: {self.state_to_hex(state)} -> {state}")
        # No MixColumns in the final round
        state = self.add_round_key(state, K2)
        if verbose: print(f"Round 2 AddK2:  {self.state_to_hex(state)} -> {state}")

        return state # Ciphertext state

    # --- Inverse AES Operations (for Decryption) ---
    def inv_sub_nibbles(self, state):
        """Performs inverse SubNibbles using the inverse S-Box."""
        return [self._sboxD[nibble] for nibble in state]

    def inv_shift_rows(self, state):
        """Performs inverse ShiftRows (which is the same as ShiftRows for 2x2)."""
        # For 2x2 matrix, ShiftRows is its own inverse
        return self.shift_rows(state)

    def inv_mix_columns(self, state):
        """Performs inverse MixColumns."""
        # For the specific matrix [[3, 2], [2, 3]], it is its own inverse in GF(2^4).
        # If a different matrix were used, its inverse would be needed here.
        return self.mix_columns(state)

    # --- Main Decryption Process ---
    def decrypt(self, ciphertext_state, key_state, verbose=True):
        """Performs Mini-AES decryption."""
        K0, K1, K2 = self.expand_key(key_state)
        if verbose:
            print(f"Using Keys for Decryption:")
            print(f"  K0: {self.state_to_hex(K0)}")
            print(f"  K1: {self.state_to_hex(K1)}")
            print(f"  K2: {self.state_to_hex(K2)}\n")

        # Start by undoing the last AddRoundKey (K2)
        state = self.add_round_key(ciphertext_state, K2)
        if verbose: print(f"Start Dec (AddK2): {self.state_to_hex(state)}")

        # Inverse Round 2 (Final Round)
        state = self.inv_shift_rows(state)
        if verbose: print(f"Inv Rnd 2 ShiftR: {self.state_to_hex(state)}")
        state = self.inv_sub_nibbles(state)
        if verbose: print(f"Inv Rnd 2 SubNib: {self.state_to_hex(state)}")

        # Inverse Round 1
        state = self.add_round_key(state, K1) # Undo AddRoundKey K1
        if verbose: print(f"Inv Rnd 1 AddK1:  {self.state_to_hex(state)}")
        state = self.inv_mix_columns(state)   # Undo MixColumns
        if verbose: print(f"Inv Rnd 1 MixCol: {self.state_to_hex(state)}")
        state = self.inv_shift_rows(state)    # Undo ShiftRows
        if verbose: print(f"Inv Rnd 1 ShiftR: {self.state_to_hex(state)}")
        state = self.inv_sub_nibbles(state)   # Undo SubNibbles
        if verbose: print(f"Inv Rnd 1 SubNib: {self.state_to_hex(state)}")

        # Final AddRoundKey K0 (Undo Initial AddRoundKey)
        state = self.add_round_key(state, K0)
        if verbose: print(f"Final Dec (AddK0): {self.state_to_hex(state)}")

        return state # Plaintext state

# =================================
# Main execution block for testing
# =================================
if __name__ == "__main__":
    mini_aes = MiniAESCorePurePython()

    pt_hex_p = "9C63"
    key_hex_p = "C3F0"

    print(f"Plaintext : {pt_hex_p}")
    print(f"Key       : {key_hex_p}\n")

    pt_state_p = mini_aes.hex_to_state(pt_hex_p)
    key_state_p = mini_aes.hex_to_state(key_hex_p)

    print("--- Enkripsi ---")
    ct_state_p = mini_aes.encrypt(pt_state_p, key_state_p)
    ct_hex_p_calc = mini_aes.state_to_hex(ct_state_p)
    print("-----------------------------")
    print(f"Calculated Ciphertext: {ct_hex_p_calc}")

    print("--- Dekripsi ---")
    dec_state_p = mini_aes.decrypt(ct_state_p, key_state_p)
    dec_hex_p_calc = mini_aes.state_to_hex(dec_state_p)
    print("-----------------------------")
    print(f"Decrypted Ciphertext : {dec_hex_p_calc}")
    print(f"Original Plaintext   : {pt_hex_p}")
    if dec_hex_p_calc == pt_hex_p:
         print("VERIFIKASI DEKRIPSI: SUCCESS\n")
    else:
         print("VERIFIKASI DEKRIPSI: FAILED\n")



# Plaintext : 9C63
# Key       : C3F0

# --- Enkripsi ---
# Calculated Keys:
#   K0: C3F0 -> [12, 3, 15, 0]
#   K1: 30FF -> [3, 0, 15, 15]
#   K2: 6696 -> [6, 6, 9, 6]

# Start    (AddK0): 5F93 -> [5, 15, 9, 3]
# Round 1 SubNib: F7A1 -> [15, 7, 10, 1]
# Round 1 ShiftR: F1A7 -> [15, 1, 10, 7]
# Round 1 MixCol: 0E3E -> [0, 14, 3, 14]
# Round 1 AddK1:  3EC1 -> [3, 14, 12, 1]
# Round 2 SubNib: 1054 -> [1, 0, 5, 4]
# Round 2 ShiftR: 1450 -> [1, 4, 5, 0]
# Round 2 AddK2:  72C6 -> [7, 2, 12, 6]
# -----------------------------
# Calculated Ciphertext: 72C6
# --- Dekripsi ---
# Using Keys for Decryption:
#   K0: C3F0
#   K1: 30FF
#   K2: 6696

# Start Dec (AddK2): 1450
# Inv Rnd 2 ShiftR: 1054
# Inv Rnd 2 SubNib: 3EC1
# Inv Rnd 1 AddK1:  0E3E
# Inv Rnd 1 MixCol: F1A7
# Inv Rnd 1 ShiftR: F7A1
# Inv Rnd 1 SubNib: 5F93
# Final Dec (AddK0): 9C63
# -----------------------------
# Decrypted Ciphertext : 9C63
# Original Plaintext   : 9C63
# VERIFIKASI DEKRIPSI: SUCCESS