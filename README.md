## Anggota Kelompok

- Muhammad Faqih Husain - 5027231023
- Kevin Anugerah Faza - 5027231027
- Athalla Barka Fadhil - 5027231018
- Muhammad Dzaky Ahnaf - 5027231039
- Harwinda - 5027231079

## Onboarding

1. pastikan `uv` sudah terinstall https://docs.astral.sh/uv/getting-started/installation/
2. `uv python install 3.10`
3. `uv venv` (pastikan menggunakan python >=3.10 )
4. `source .venv/bin/activate`
5. `uv run main.py`

## How to run

### Enkripsi teks dengan ECB (verbose mode)

`uv run main.py encrypt "Hello" A73B -v`

### Dekripsi file dengan CBC

`uv run main.py decrypt cipher.bin A73B -m CBC -f -o plain.txt`

### Enkripsi hex dengan CBC

`uv run main.py encrypt 9C63 C3F0 -m CBC`

### Uji Avalanche Effect

`uv run main.py encrypt 9C63 C3F0 --avalanche`

### Contoh

`uv run main.py encrypt plain.txt A73B -m CBC -f -o cipher.bin`
`uv run main.py decrypt cipher.bin A73B -m CBC -f -o decrypted.txt`


## Analisis Keamanan Sensitivitas dan Avalanche Effect

- Uji sensitivitas terhadap perubahan 1-bit di plaintext atau key:

Kode ini diimplementasikan dalam fungsi `test_avalanche_effect` di file `main.py`. Fungsi ini secara acak memilih satu bit pada plaintext atau kunci, membaliknya (`XOR` dengan bitmask), mengenkripsi ulang data dengan input yang telah dimodifikasi tersebut, dan membandingkan hasilnya dengan ciphertext original menggunakan Hamming Distance.

- Avalanche Effect

Pada Avalanche, Perubahan kecil pada input (misalnya, mengubah hanya *satu bit* pada plaintext atau kunci) harus menyebabkan perubahan yang signifikan dan tampak acak pada output (ciphertext).

Pengaplikasiannya disini adalah dengan mengukur efek avalanche menggunakan penghitungan **jumlah bit yang berbeda** (menggunakan Hamming Distance) antara ciphertext asli dan ciphertext yang dihasilkan setelah perubahan 1-bit pada input.

Idealnya, perubahan 1-bit input akan menyebabkan sekitar 50% bit pada ciphertext berubah (misalnya, ~8 bit untuk blok 16-bit pada Mini-AES ini). Semakin dekat ke 50%, semakin baik efek avalanche-nya, yang menunjukkan difusi perubahan yang baik di seluruh ciphertext dan menyulitkan analisis kriptografi.