# Program Autokey Cipher Encryption & Decryption

Aplikasi ini merupakan implementasi **Autokey Cipher** berbasis **Python & Streamlit**, yang dapat melakukan proses **enkripsi** dan **dekripsi**, baik melalui *input teks*, *upload file teks (.txt)*, maupun *upload file biner* (misal `.pdf`, `.jpg`, `.exe`). Aplikasi dapat dijalankan secara lokal maupun secara online (public deploy).


## Anggota

| No | Nama                 | NPM           |
|----|----------------------|---------------|
| 1  | Marchellin Chenika   | 140810230002  |
| 2  | Nazwa Nashatasya     | 140810230019  |
| 3  | Naqiyyah Zhahirah    | 140810230039  |


## 📘 Deskripsi Singkat

**Autokey Cipher** adalah salah satu cipher klasik yang menggunakan kunci (*key*) dan teks asli (*plaintext*) sebagai bagian dari kunci berikutnya. Metode ini lebih aman dibandingkan Vigenère Cipher standar.

Aplikasi ini menyediakan:
- Enkripsi teks → menghasilkan ciphertext
- Dekripsi ciphertext → menghasilkan plaintext kembali
- Enkripsi/dekripsi file `.txt` maupun file biner (misal: `.pdf`, `.jpg`, `.exe`)
- Upload file untuk diproses, dan download output hasil enkripsi/dekripsi
- Tabel proses enkripsi/dekripsi untuk teks (step-by-step debugging)
- Mode interaktif melalui Streamlit
- Tab Find Key untuk analisis key dari ciphertext

---


## Fitur Program

### A. Teks (.txt)

1. **Enkripsi Autokey**
   - Input:  
     - Teks manual atau upload file `.txt`  
     - Key (huruf A–Z)  
   - Output:  
     - Ciphertext  
     - Tabel proses enkripsi per huruf (nilai numerik & pergeseran)  
     - Preview file hasil enkripsi sebelum download

2. **Dekripsi Autokey**
   - Input:  
     - Ciphertext manual atau file `.txt`  
   - Output:  
     - Plaintext  
     - Tabel proses dekripsi per huruf (key tiap langkah)  
     - Preview file hasil dekripsi sebelum download

---

### B. File Biner (misal: .pdf, .jpg, .exe)

1. **Enkripsi File Biner**
   - Input:
     - Nama file sumber (misal: `file_awal.pdf`)
     - Nama file output (misal: `file_hasil.pdf.enc`)
     - Key (huruf A–Z)
   - Output:
     - File baru yang sudah terenkripsi
     - Semua byte termasuk header ikut terenkripsi
     - Preview metadata dasar file hasil enkripsi

2. **Dekripsi File Biner**
   - Input:
     - File biner terenkripsi (misal: `file_hasil.pdf.enc`)
     - Key (huruf A–Z)
   - Output:
     - File asli kembali (misal: `file_didekripsi.pdf`)
     - Semua byte dikembalikan, termasuk header
     - Preview metadata dasar file hasil dekripsi

---

### C. Mode Interaktif (Streamlit)

- UI sederhana, responsif, mudah digunakan
- Expander untuk menampilkan step-by-step debugging dan tips keamanan
- Bisa dijalankan online via Streamlit
- Mendukung semua fitur teks maupun biner melalui tab interaktif

---

### D. Find Key (Tab Terpisah)

- **Tujuan:** Membantu menemukan key jika key asli tidak diketahui
- **Input:**  
  - Ciphertext manual atau file `.txt`  
  - Jika pakai file: harus ada **dua file terpisah**:
    1. File plaintext (.txt)
    2. File ciphertext (.txt)
- **Output:**  
  - Prediksi key kemungkinan dipakai  
  - Analisis frekuensi karakter  
  - Tabel step-by-step pencarian key  
- **Catatan:**  
  - Hanya untuk teks (.txt), bukan file biner  
  - Hanya **isi file** yang diproses; header dan metadata file `.txt` tetap utuh  

---

## Catatan
- Untuk **teks (.txt)**:
  - Hanya **isi file** yang diproses saat enkripsi/dekripsi; header dan metadata tetap utuh.
  - Jika menggunakan **Find Key** berbasis file, harus ada **dua file terpisah**:  
    1. File plaintext (.txt)  
    2. File ciphertext (.txt)

- Untuk **file biner (misal: .pdf, .jpg, .exe)**:
  - Seluruh konten file (termasuk header dan metadata) ikut dienkripsi/dekripsi.
  - File output **tidak bisa dibuka langsung** karena format asli rusak.
  - **Find Key** tidak berlaku untuk file biner.