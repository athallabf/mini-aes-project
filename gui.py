import tkinter as tk
from tkinter import messagebox
from encrypt_decrypt import MiniAESCorePurePython  # Asumsikan kamu simpan kelas kamu di file pts_updated.py

# Inisialisasi Mini-AES
mini_aes = MiniAESCorePurePython()

def encrypt_action():
    try:
        plaintext_hex = entry_plaintext.get().strip().upper()
        key_hex = entry_key.get().strip().upper()

        # Validasi panjang input
        if len(plaintext_hex) != 4 or len(key_hex) != 4:
            messagebox.showerror("Error", "Plaintext dan Key harus 4 digit heksa (contoh: 1A2B).")
            return

        # Konversi ke state
        pt_state = mini_aes.hex_to_state(plaintext_hex)
        key_state = mini_aes.hex_to_state(key_hex)

        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"Plaintext : {plaintext_hex}\n")
        output_text.insert(tk.END, f"Key       : {key_hex}\n\n")
        output_text.insert(tk.END, "--- ENCRYPTION ---\n")

        # Tangkap output verbose ke textbox
        class VerboseCapture:
            def write(self, msg):
                output_text.insert(tk.END, msg)
            def flush(self):
                pass

        import sys
        old_stdout = sys.stdout
        sys.stdout = capture = VerboseCapture()

        ct_state = mini_aes.encrypt(pt_state, key_state, verbose=True)
        ct_hex = mini_aes.state_to_hex(ct_state)

        sys.stdout = old_stdout  # Kembalikan stdout normal

        output_text.insert(tk.END, "\nCiphertext: " + ct_hex + "\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    try:
        ciphertext_hex = entry_ciphertext.get().strip().upper()
        key_hex = entry_key.get().strip().upper()

        if len(ciphertext_hex) != 4 or len(key_hex) != 4:
            messagebox.showerror("Error", "Ciphertext dan Key harus 4 digit heksa (contoh: 1A2B).")
            return

        ct_state = mini_aes.hex_to_state(ciphertext_hex)
        key_state = mini_aes.hex_to_state(key_hex)

        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"Ciphertext : {ciphertext_hex}\n")
        output_text.insert(tk.END, f"Key        : {key_hex}\n\n")
        output_text.insert(tk.END, "--- DECRYPTION ---\n")

        # Tangkap output verbose ke textbox
        class VerboseCapture:
            def write(self, msg):
                output_text.insert(tk.END, msg)
            def flush(self):
                pass

        import sys
        old_stdout = sys.stdout
        sys.stdout = capture = VerboseCapture()

        pt_state = mini_aes.decrypt(ct_state, key_state, verbose=True)
        pt_hex = mini_aes.state_to_hex(pt_state)

        sys.stdout = old_stdout

        output_text.insert(tk.END, "\nPlaintext: " + pt_hex + "\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- GUI Setup ---
root = tk.Tk()
root.title("Mini-AES Encryptor & Decryptor")

tk.Label(root, text="Plaintext (4 hex digit):").pack()
entry_plaintext = tk.Entry(root)
entry_plaintext.pack()

tk.Label(root, text="Key (4 hex digit):").pack()
entry_key = tk.Entry(root)
entry_key.pack()

tk.Label(root, text="Ciphertext (4 hex digit) [Untuk Decrypt]:").pack()
entry_ciphertext = tk.Entry(root)
entry_ciphertext.pack()

frame_buttons = tk.Frame(root)
frame_buttons.pack()

btn_encrypt = tk.Button(frame_buttons, text="Encrypt", command=encrypt_action)
btn_encrypt.pack(side=tk.LEFT, padx=5, pady=5)

btn_decrypt = tk.Button(frame_buttons, text="Decrypt", command=decrypt_action)
btn_decrypt.pack(side=tk.LEFT, padx=5, pady=5)

output_text = tk.Text(root, height=25, width=70)
output_text.pack()

root.mainloop()
