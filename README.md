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

### Contoh

`uv run main.py encrypt plain.txt A73B -m CBC -f -o cipher.bin`
`uv run main.py decrypt cipher.bin A73B -m CBC -f -o decrypted.txt`
