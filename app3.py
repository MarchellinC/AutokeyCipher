import streamlit as st
import pandas as pd
import re
from io import BytesIO
import base64

# ======================================================
# HELPER FUNCTIONS
# ======================================================
def charToNum(c):
    return ord(c) - ord("A")

def numToChar(n):
    return chr(n + ord("A"))

def normalizeText(s: str) -> str:
    s = s.replace("\r", "\n")
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def onlyLettersUpper(s: str) -> str:
    return re.sub(r"[^A-Z]", "", s.upper())

# ======================================================
# TEXT ENCRYPTION (Autokey Cipher)
# ======================================================
def autokeyEncrypt(plaintext, key):
    plaintext = normalizeText(plaintext).upper()
    key = onlyLettersUpper(key)

    keyStream = list(key)
    ciphertext = ""

    table = {
        "PT": [], "n(PT)": [],
        "K": [], "n(K)": [],
        "(nPT+nK)%26": [],
        "CT": [], "n(CT)": [],
        "KeyStream": []
    }

    ki = 0
    for c in plaintext:
        if c == " ":
            ciphertext += " "
            table["PT"].append(" ")
            table["n(PT)"].append("")
            table["K"].append("")
            table["n(K)"].append("")
            table["(nPT+nK)%26"].append("")
            table["CT"].append(" ")
            table["n(CT)"].append("")
            table["KeyStream"].append("".join(keyStream))
            continue

        if not c.isalpha():
            continue

        while ki < len(keyStream) and not keyStream[ki].isalpha():
            ki += 1

        if ki < len(keyStream):
            k = keyStream[ki]
        else:
            k = "A"

        ptN = charToNum(c)
        kN = charToNum(k)
        ctN = (ptN + kN) % 26
        ct = numToChar(ctN)

        ciphertext += ct
        keyStream.append(c)
        ki += 1

        table["PT"].append(c)
        table["n(PT)"].append(ptN)
        table["K"].append(k)
        table["n(K)"].append(kN)
        table["(nPT+nK)%26"].append(ctN)
        table["CT"].append(ct)
        table["n(CT)"].append(ctN)
        table["KeyStream"].append("".join(keyStream))

    return ciphertext, pd.DataFrame(table)

# ======================================================
# TEXT DECRYPTION (Autokey Cipher)
# ======================================================
def autokeyDecrypt(ciphertext, key):
    ciphertext = normalizeText(ciphertext).upper()
    key = onlyLettersUpper(key)

    keyStream = list(key)
    plaintext = ""

    table = {
        "CT": [], "n(CT)": [],
        "K": [], "n(K)": [],
        "(nCT-nK)%26": [],
        "PT": [], "n(PT)": [],
        "KeyStream": []
    }

    ki = 0
    for c in ciphertext:
        if c == " ":
            plaintext += " "
            table["CT"].append(" ")
            table["n(CT)"].append("")
            table["K"].append("")
            table["n(K)"].append("")
            table["(nCT-nK)%26"].append("")
            table["PT"].append(" ")
            table["n(PT)"].append("")
            table["KeyStream"].append("".join(keyStream))
            continue

        if not c.isalpha():
            continue

        while ki < len(keyStream) and not keyStream[ki].isalpha():
            ki += 1

        if ki < len(keyStream):
            k = keyStream[ki]
        else:
            k = "A"

        ctN = charToNum(c)
        kN = charToNum(k)
        ptN = (ctN - kN) % 26
        pt = numToChar(ptN)

        plaintext += pt
        keyStream.append(pt)
        ki += 1

        table["CT"].append(c)
        table["n(CT)"].append(ctN)
        table["K"].append(k)
        table["n(K)"].append(kN)
        table["(nCT-nK)%26"].append(ptN)
        table["PT"].append(pt)
        table["n(PT)"].append(ptN)
        table["KeyStream"].append("".join(keyStream))

    return plaintext, pd.DataFrame(table)

# ======================================================
# FIND KEY (Key Recovery Attack)
# ======================================================
def findKey(plaintext, ciphertext):
    plaintext = normalizeText(plaintext).upper()
    ciphertext = normalizeText(ciphertext).upper()

    keystream = ""
    table = {
        "PT": [], "n(PT)": [],
        "CT": [], "n(CT)": [],
        "(nCT-nPT)%26": [],
        "Key": [], "n(Key)": []
    }

    for pt, ct in zip(plaintext, ciphertext):
        if not pt.isalpha() or not ct.isalpha():
            table["PT"].append(pt)
            table["n(PT)"].append("")
            table["CT"].append(ct)
            table["n(CT)"].append("")
            table["(nCT-nPT)%26"].append("")
            table["Key"].append(" ")
            table["n(Key)"].append("")
            continue

        ptN = charToNum(pt)
        ctN = charToNum(ct)
        kN = (ctN - ptN) % 26
        k = numToChar(kN)

        keystream += k

        table["PT"].append(pt)
        table["n(PT)"].append(ptN)
        table["CT"].append(ct)
        table["n(CT)"].append(ctN)
        table["(nCT-nPT)%26"].append(kN)
        table["Key"].append(k)
        table["n(Key)"].append(kN)

    plain_no_space = onlyLettersUpper(plaintext)
    idx = keystream.find(plain_no_space[:5])
    if idx != -1:
        real_key = keystream[:idx]
    else:
        real_key = keystream

    return real_key, pd.DataFrame(table)

# ======================================================
# BINARY FILE ENCRYPTION (File Biner Implementation)
# ======================================================
def autokeyEncryptBytes(data: bytes, key: str) -> bytes:
    """
    Enkripsi file biner byte-per-byte menggunakan Autokey Cipher.
    Header file ikut terenkripsi sehingga file tidak bisa dibuka.
    """
    if not key:
        raise ValueError("Key tidak boleh kosong!")
    
    key_bytes = key.encode("utf-8")
    keyStream = bytearray(key_bytes)
    result = bytearray()

    for i, b in enumerate(data):
        if i < len(keyStream):
            k = keyStream[i]
        else:
            k = keyStream[i % len(key_bytes)]
        
        ct = (b + k) % 256
        result.append(ct)
        keyStream.append(b)

    return bytes(result)

# ======================================================
# BINARY FILE DECRYPTION (File Biner Implementation)
# ======================================================
def autokeyDecryptBytes(data: bytes, key: str) -> bytes:
    """
    Dekripsi file biner byte-per-byte menggunakan Autokey Cipher.
    File akan kembali ke kondisi semula dan bisa dibuka.
    """
    if not key:
        raise ValueError("Key tidak boleh kosong!")
    
    key_bytes = key.encode("utf-8")
    keyStream = bytearray(key_bytes)
    result = bytearray()

    for i, b in enumerate(data):
        if i < len(keyStream):
            k = keyStream[i]
        else:
            k = keyStream[i % len(key_bytes)]
        
        pt = (b - k) % 256
        result.append(pt)
        keyStream.append(pt)

    return bytes(result)

# ======================================================
# UI STYLING — Pastel Pink & Blue Soft Theme
# ======================================================
st.set_page_config(page_title="Autokey Cipher", page_icon="🔐", layout="wide")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');

    * {
        font-family: 'Poppins', sans-serif !important;
    }

    /* Background pastel soft */
    .stApp {
        background: linear-gradient(135deg, #ffe7f3 0%, #e3f0ff 50%, #f9e6ff 100%);
    }

    /* HEADER ================================================== */
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: rgba(255, 255, 255, 0.9);
        border-radius: 20px;
        margin-bottom: 2rem;
        box-shadow: 0 6px 20px rgba(255, 182, 193, 0.25);
    }

    .main-header h1 {
        color: #ff9ac9;
        font-size: 3rem;
        font-weight: 700;
        margin: 0;
        text-shadow: 2px 2px 4px rgba(255, 182, 193, 0.25);
    }

    .main-header p {
        color: #7ba7ff;
        font-size: 1.2rem;
        margin-top: 0.5rem;
        font-weight: 500;
    }

    /* INFO CARD ================================================== */
    .info-card {
        background: rgba(255, 255, 255, 0.95);
        padding: 1.5rem;
        border-radius: 18px;
        margin: 1rem 0;
        box-shadow: 0 4px 14px rgba(255, 182, 193, 0.25);
        border-left: 5px solid #ffb8e6;
    }

    .info-card h3 {
        color: #ff87c4;
        margin-top: 0;
        font-weight: 600;
    }

    /* FEATURE BOX ================================================== */
    .feature-box {
        background: linear-gradient(135deg, #ffd4ec 0%, #cfe3ff 100%);
        padding: 1.5rem;
        border-radius: 18px;
        margin: 1rem 0;
        color: #4a4a4a;
        box-shadow: 0 4px 16px rgba(255, 182, 193, 0.3);
        border: 2px solid rgba(255, 182, 193, 0.5);
    }

    /* BUTTON ================================================== */
    .stButton>button {
        background: linear-gradient(135deg, #ff9ac9 0%, #a4c6ff 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        border-radius: 30px;
        font-weight: 600;
        font-size: 1.1rem;
        box-shadow: 0 4px 15px rgba(255, 182, 193, 0.5);
        transition: all 0.3s ease;
    }

    .stButton>button:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 22px rgba(255, 182, 193, 0.7);
    }

    /* INPUT FIELD ================================================== */
    .stTextInput>div>div, 
    .stTextArea>div>div, 
    .stSelectbox>div>div {
        background: rgba(255, 255, 255, 0.85);
        border-radius: 12px;
        border: 2px solid #ffc5e5;
        padding: 0.5rem 1rem;
    }

    /* FILE UPLOADER ================================================== */
    .stFileUploader {
        background: rgba(255, 255, 255, 0.85);
        padding: 1.5rem;
        border-radius: 18px;
        border: 2px dashed #a4c6ff;
        box-shadow: 0 4px 12px rgba(164, 198, 255, 0.4);
    }

    /* SUCCESS BOX ================================================== */
    .success-box {
        background: linear-gradient(135deg, #e7fff6 0%, #ffe6f3 100%);
        padding: 1rem;
        border-radius: 12px;
        margin: 1rem 0;
        border-left: 5px solid #89ffd8;
        box-shadow: 0 4px 14px rgba(160, 255, 224, 0.4);
    }

    /* EXPANDER ================================================== */
    div[data-testid="stExpander"] > button {
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;  /* jarak ikon & teks */
        font-size: 1.1rem !important;
    }

    div[data-testid="stExpander"] {
        background: rgba(255, 255, 255, 0.85);
        border-radius: 15px;
        border: 2px solid #cfe3ff;
        box-shadow: 0 4px 14px rgba(164, 198, 255, 0.3);
    }

    /* PREVIEW BOX ================================================== */
    .preview-box {
        background: rgba(255, 255, 255, 0.9);
        padding: 1rem;
        border-radius: 12px;
        border-left: 5px solid #7ba7ff;
        margin: 1rem 0;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ======================================================
# HEADER
# ======================================================
st.markdown("""
    <div class="main-header">
        <h1>🔐 Autokey Cipher</h1>
        <p>Advanced Cryptography Application - Complete File Encryption System</p>
    </div>
""", unsafe_allow_html=True)

# ======================================================
# SIDEBAR - INFORMASI
# ======================================================
with st.sidebar:
    st.markdown("### 📚 Tentang Autokey Cipher")
    st.markdown("""
    **Autokey Cipher** adalah pengembangan dari Vigenère Cipher yang menggunakan plaintext 
    sebagai bagian dari kunci, membuatnya lebih aman terhadap analisis frekuensi.
    
    **Cara Kerja:**
    - Kunci awal digunakan untuk enkripsi karakter pertama
    - Karakter plaintext menjadi bagian dari keystream
    - Setiap karakter menggunakan key yang berbeda
    
    **Rumus:**
    - Enkripsi: `C = (P + K) mod 26`
    - Dekripsi: `P = (C - K) mod 26`
    """)
    
    st.markdown("---")
    st.markdown("### ✨ Fitur Aplikasi")
    st.markdown("""
    - ✅ Enkripsi/Dekripsi Teks
    - ✅ Enkripsi File Sembarang (PDF, DOCX, PNG, dll)
    - ✅ Key Recovery Attack
    - ✅ Detail Proses Kriptografi
    - ✅ Download Hasil
    - ✅ Modern UI
    """)
    
    st.markdown("---")
    st.markdown("### 📋 Format File Input")
    st.markdown("""
    **File yang Didukung:**
    - **Teks:** .txt, .md, .csv
    - **Dokumen:** .pdf, .docx, .xlsx
    - **Gambar:** .png, .jpg, .jpeg, .gif
    - **Media:** .mp3, .mp4, .avi
    - **Dan semua jenis file lainnya!**
    
    **Catatan Penting:**
    - File terenkripsi akan memiliki ekstensi `.enc`
    - Header file ikut terenkripsi
    - File tidak bisa dibuka sebelum didekripsi
    - Gunakan key yang sama untuk dekripsi
    """)

# ======================================================
# MAIN CONTENT
# ======================================================

tab1, tab2, tab3 = st.tabs(["🔐 Enkripsi/Dekripsi", "🔍 Find Key", "📖 Panduan Lengkap"])

# ======================================================
# TAB 1: ENKRIPSI/DEKRIPSI
# ======================================================
with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        input_type = st.selectbox(
            "📥 Pilih Tipe Input:",
            ["Teks Manual", "File Teks (.txt)", "File Sembarang (PDF, DOCX, PNG, dll)"],
            help="Pilih tipe input yang ingin Anda enkripsi/dekripsi"
        )
    
    with col2:
        operation = st.selectbox(
            "⚙️ Pilih Operasi:",
            ["Enkripsi", "Dekripsi"]
        )
    
    st.markdown("---")
    
    # INPUT TEKS MANUAL
    if input_type == "Teks Manual":
        text_input = st.text_area(
            "📝 Masukkan Teks:",
            height=150,
            placeholder="Ketik atau paste teks Anda di sini..."
        )
        
        key_input = st.text_input(
            "🔑 Masukkan Key (huruf A-Z saja):",
            placeholder="Contoh: SECRET",
            help="Key hanya boleh berisi huruf A-Z"
        )
        
        if st.button("🚀 Proses", use_container_width=True):
            if not text_input:
                st.error("❌ Teks tidak boleh kosong!")
            elif not key_input:
                st.error("❌ Key tidak boleh kosong!")
            else:
                with st.spinner("Memproses..."):
                    if operation == "Enkripsi":
                        result, df = autokeyEncrypt(text_input, key_input)
                        st.success("✅ Enkripsi Berhasil!")
                        
                        st.markdown("### 📤 Hasil Ciphertext:")
                        st.code(result, language=None)
                        
                        st.download_button(
                            "💾 Download Ciphertext",
                            result,
                            "ciphertext.txt",
                            use_container_width=True
                        )
                        
                        with st.expander("📊 Lihat Detail Proses Enkripsi"):
                            st.dataframe(df, use_container_width=True)
                    
                    else:
                        result, df = autokeyDecrypt(text_input, key_input)
                        st.success("✅ Dekripsi Berhasil!")
                        
                        st.markdown("### 📥 Hasil Plaintext:")
                        st.code(result, language=None)
                        
                        st.download_button(
                            "💾 Download Plaintext",
                            result,
                            "plaintext.txt",
                            use_container_width=True
                        )
                        
                        with st.expander("📊 Lihat Detail Proses Dekripsi"):
                            st.dataframe(df, use_container_width=True)
    
    # INPUT FILE TEKS 
    elif input_type == "File Teks (.txt)":
        uploaded_file = st.file_uploader(
            "📁 Upload File Teks (.txt)",
            type=["txt"],
            help="Upload file teks yang ingin diproses",
            key="txt_file_uploader"
        )
        
        # Preview file jika sudah diupload
        if uploaded_file is not None:
            # Baca file untuk preview
            file_content = uploaded_file.read().decode("utf-8")
            uploaded_file.seek(0)  # Reset pointer untuk dibaca lagi nanti
            
            st.markdown("**📄 Preview File:**")
            preview_text = file_content[:500] + ("..." if len(file_content) > 500 else "")
            st.markdown(f'<div class="preview-box"><pre>{preview_text}</pre></div>', 
                    unsafe_allow_html=True)
            
            # Info file
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"📄 **Nama File:** {uploaded_file.name}")
            with col2:
                st.info(f"📊 **Ukuran:** {len(file_content)} karakter")
        
        key_input = st.text_input(
            "🔑 Masukkan Key:",
            placeholder="Contoh: MYSECRET",
            key="txt_key_input"
        )
        
        if st.button("🚀 Proses File", use_container_width=True, key="txt_process_btn"):
            if uploaded_file is None:
                st.error("❌ Upload file terlebih dahulu!")
            elif not key_input:
                st.error("❌ Key tidak boleh kosong!")
            else:
                try:
                    with st.spinner("Memproses file..."):
                        # Baca konten file
                        content = uploaded_file.read().decode("utf-8")
                        
                        if operation == "Enkripsi":
                            result, df = autokeyEncrypt(content, key_input)
                            st.success("✅ File Berhasil Dienkripsi!")
                            
                            st.markdown("### 📤 Hasil Enkripsi:")
                            preview_result = result[:500] + ("..." if len(result) > 500 else "")
                            st.code(preview_result, language=None)
                            
                            # Informasi hasil
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("📊 Panjang Original", f"{len(content)} karakter")
                            with col2:
                                st.metric("📊 Panjang Terenkripsi", f"{len(result)} karakter")

                            st.download_button(
                                "💾 Download File Terenkripsi",
                                result,
                                f"{uploaded_file.name}_encrypted.txt",
                                use_container_width=True
                            )
                            
                            with st.expander("📊 Lihat Detail Proses (100 baris pertama)"):
                                st.dataframe(df.head(100), use_container_width=True)
                                st.info(f"ℹ️ Total {len(df)} baris proses enkripsi")
                        
                        else:  # Dekripsi
                            result, df = autokeyDecrypt(content, key_input)
                            st.success("✅ File Berhasil Didekripsi!")
                            
                            st.markdown("### 📥 Hasil Dekripsi:")
                            preview_result = result[:500] + ("..." if len(result) > 500 else "")
                            st.code(preview_result, language=None)
                            
                            # Informasi hasil
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("📊 Panjang Terenkripsi", f"{len(content)} karakter")
                            with col2:
                                st.metric("📊 Panjang Didekripsi", f"{len(result)} karakter")
  
                            output_filename = f"{uploaded_file.name}_decrypted.txt"
                            
                            st.download_button(
                                "💾 Download File Hasil Dekripsi",
                                result,
                                output_filename,
                                use_container_width=True
                            )
                            
                            with st.expander("📊 Lihat Detail Proses (100 baris pertama)"):
                                st.dataframe(df.head(100), use_container_width=True)
                                st.info(f"ℹ️ Total {len(df)} baris proses dekripsi")
                
                except UnicodeDecodeError:
                    st.error("❌ File tidak dapat dibaca sebagai teks UTF-8. Pastikan file adalah file teks yang valid.")
                except Exception as e:
                    st.error(f"❌ Terjadi kesalahan: {str(e)}")

    # INPUT FILE SEMBARANG (File Biner)
    else:
        st.markdown("""
        <div class="info-card">
            <h3>🔒 Enkripsi File Biner - Implementasi File Biner</h3>
            <p>Fitur ini mengenkripsi <strong>seluruh byte dalam file</strong>, termasuk header. 
            File yang terenkripsi tidak akan bisa dibuka sampai didekripsi kembali dengan key yang benar.</p>
            <p><strong>Mendukung:</strong> PDF, DOCX, XLSX, PNG, JPG, MP3, MP4, ZIP, dan semua format file!</p>
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "📁 Upload File Sembarang",
            type=None,
            help="Upload file apapun: dokumen, gambar, video, dll"
        )
        
        if uploaded_file:
            file_details = {
                "Nama File": uploaded_file.name,
                "Tipe": uploaded_file.type if uploaded_file.type else "Unknown",
                "Ukuran": f"{uploaded_file.size / 1024:.2f} KB"
            }
            
            col1, col2, col3 = st.columns(3)
            col1.metric("📄 Nama", file_details["Nama File"])
            col2.metric("📦 Tipe", file_details["Tipe"])
            col3.metric("💾 Ukuran", file_details["Ukuran"])
        
        key_input = st.text_input(
            "🔑 Masukkan Key untuk Enkripsi/Dekripsi:",
            placeholder="Contoh: STRONGKEY123",
            help="Key bisa berisi huruf, angka, dan simbol"
        )
        
        if st.button("🚀 Proses File", use_container_width=True):
            if not uploaded_file:
                st.error("❌ Upload file terlebih dahulu!")
            elif not key_input:
                st.error("❌ Key tidak boleh kosong!")
            else:
                try:
                    with st.spinner(f"{'Mengenkripsi' if operation == 'Enkripsi' else 'Mendekripsi'} file..."):
                        file_bytes = uploaded_file.read()
                        
                        if operation == "Enkripsi":
                            encrypted_bytes = autokeyEncryptBytes(file_bytes, key_input)
                            
                            st.success("✅ File Berhasil Dienkripsi!")
                            st.markdown("""
                            <div class="success-box">
                                <strong>✨ Proses Enkripsi Selesai!</strong><br>
                                ✓ Seluruh byte file telah terenkripsi<br>
                                ✓ Header file tidak dapat dibaca<br>
                                ✓ File tidak bisa dibuka tanpa dekripsi<br>
                                ✓ Gunakan key yang sama untuk dekripsi
                            </div>
                            """, unsafe_allow_html=True)
                            
                            output_filename = f"{uploaded_file.name}.enc"
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("📊 Ukuran Original", f"{len(file_bytes)} bytes")
                            with col2:
                                st.metric("📊 Ukuran Terenkripsi", f"{len(encrypted_bytes)} bytes")
                            
                            st.download_button(
                                "💾 Download File Terenkripsi",
                                encrypted_bytes,
                                output_filename,
                                use_container_width=True
                            )
                        
                        else:
                            decrypted_bytes = autokeyDecryptBytes(file_bytes, key_input)
                            
                            st.success("✅ File Berhasil Didekripsi!")
                            st.markdown("""
                            <div class="success-box">
                                <strong>✨ Proses Dekripsi Selesai!</strong><br>
                                ✓ File telah dikembalikan ke kondisi semula<br>
                                ✓ Header file telah dipulihkan<br>
                                ✓ File sekarang dapat dibuka kembali
                            </div>
                            """, unsafe_allow_html=True)
                            
                            output_filename = uploaded_file.name.replace(".enc", "")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("📊 Ukuran Terenkripsi", f"{len(file_bytes)} bytes")
                            with col2:
                                st.metric("📊 Ukuran Didekripsi", f"{len(decrypted_bytes)} bytes")
                            
                            st.download_button(
                                "💾 Download File Hasil Dekripsi",
                                decrypted_bytes,
                                output_filename,
                                use_container_width=True
                            )
                
                except Exception as e:
                    st.error(f"❌ Terjadi kesalahan: {str(e)}")
                    st.info("💡 Pastikan Anda menggunakan key yang benar untuk dekripsi!")
            
# ======================================================
# TAB 2: FIND KEY
# ======================================================
with tab2:
    st.markdown("""
    <div class="info-card">
        <h3>🔍 Key Recovery Attack</h3>
        <p>Fitur ini memungkinkan Anda menemukan key yang digunakan untuk enkripsi 
        jika Anda memiliki plaintext dan ciphertext yang sesuai.</p>
        <p><strong>Catatan:</strong> Ini adalah serangan kriptanalisis known-plaintext attack.</p>
    </div>
    """, unsafe_allow_html=True)
    
    input_method = st.radio(
        "Pilih Metode Input:",
        ["Input Manual", "Upload File"]
    )
    
    if input_method == "Input Manual":
        plaintext = st.text_area(
            "📝 Masukkan Plaintext:",
            height=150,
            placeholder="Masukkan plaintext asli..."
        )
        
        ciphertext = st.text_area(
            "🔐 Masukkan Ciphertext:",
            height=150,
            placeholder="Masukkan ciphertext yang sesuai..."
        )
        
        if st.button("🔍 Cari Key", use_container_width=True):
            if not plaintext or not ciphertext:
                st.error("❌ Plaintext dan Ciphertext harus diisi!")
            else:
                with st.spinner("Mencari key..."):
                    found_key, df = findKey(plaintext, ciphertext)
                    
                    st.success("✅ Key Berhasil Ditemukan!")
                    
                    st.markdown("### 🔑 Key yang Ditemukan:")
                    st.code(found_key, language=None)
                    
                    st.download_button(
                        "💾 Download Key",
                        found_key,
                        "found_key.txt",
                        use_container_width=True
                    )
                    
                    with st.expander("📊 Lihat Detail Analisis"):
                        st.dataframe(df, use_container_width=True)
    
    else:
        col1, col2 = st.columns(2)
        
        with col1:
            pt_file = st.file_uploader("📁 Upload Plaintext File", type=["txt"], key="pt")
        
        with col2:
            ct_file = st.file_uploader("📁 Upload Ciphertext File", type=["txt"], key="ct")
        
        if st.button("🔍 Cari Key dari File", use_container_width=True):
            if not pt_file or not ct_file:
                st.error("❌ Upload kedua file terlebih dahulu!")
            else:
                with st.spinner("Menganalisis file..."):
                    plaintext = pt_file.read().decode("utf-8")
                    ciphertext = ct_file.read().decode("utf-8")
                    
                    found_key, df = findKey(plaintext, ciphertext)
                    
                    st.success("✅ Key Berhasil Ditemukan dari File!")
                    
                    st.markdown("### 🔑 Key yang Ditemukan:")
                    st.code(found_key, language=None)
                    
                    st.download_button(
                        "💾 Download Key",
                        found_key,
                        "found_key.txt",
                        use_container_width=True
                    )
                    
                    with st.expander("📊 Lihat Detail Analisis"):
                        st.dataframe(df.head(100), use_container_width=True)

# ======================================================
# TAB 3: PANDUAN
# ======================================================
with tab3:
    st.markdown("""
    <div class="info-card">
        <h3>📖 Panduan Lengkap Autokey Cipher</h3>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Penjelasan Autokey Cipher
    with st.expander("📚 Apa itu Autokey Cipher?", expanded=True):
        st.markdown("""
        **Autokey Cipher** adalah metode enkripsi substitusi polialfabetik yang dikembangkan 
        oleh Blaise de Vigenère pada abad ke-16 dan disempurnakan oleh berbagai kriptografer.
        
        **Keunggulan dibanding Vigenère Cipher:**
        - ✅ Tidak ada pola kunci yang berulang
        - ✅ Lebih tahan terhadap analisis frekuensi
        - ✅ Keystream yang lebih panjang dan unik
        - ✅ Lebih sulit untuk di-crack dengan metode Kasiski
        
        **Cara Kerja:**
        1. Dimulai dengan key awal (misalnya: "SECRET")
        2. Key digunakan untuk enkripsi karakter pertama plaintext
        3. Karakter plaintext kemudian ditambahkan ke keystream
        4. Keystream terus bertambah dengan plaintext yang telah dienkripsi
        5. Proses berlanjut hingga seluruh plaintext terenkripsi
        """)
    
    # Contoh Enkripsi
    with st.expander("🔐 Contoh Proses Enkripsi"):
        st.markdown("""
        **Plaintext:** `HELLO WORLD`  
        **Key:** `SECRET`
        
        | Step | PT | n(PT) | K | n(K) | (PT+K)%26 | CT | KeyStream |
        |------|----|----|----|----|-----------|----|----|
        | 1 | H | 7 | S | 18 | 25 | Z | SECRET |
        | 2 | E | 4 | E | 4 | 8 | I | SECRETH |
        | 3 | L | 11 | C | 2 | 13 | N | SECRETHE |
        | 4 | L | 11 | R | 17 | 2 | C | SECRETHEL |
        | 5 | O | 14 | E | 4 | 18 | S | SECRETHELL |
        | 6 | W | 22 | T | 19 | 15 | P | SECRETHELLO |
        | 7 | O | 14 | H | 7 | 21 | V | SECRETHELLOW |
        | 8 | R | 17 | E | 4 | 21 | V | SECRETHELLOWO |
        | 9 | L | 11 | L | 11 | 22 | W | SECRETHELLOWOR |
        | 10 | D | 3 | L | 11 | 14 | O | SECRETHELLOWORL |
        
        **Hasil Ciphertext:** `ZINCS PVVWO`
        
        **Penjelasan:**
        - Setiap karakter plaintext menggunakan key yang berbeda
        - Key bertambah dengan menambahkan plaintext ke keystream
        - Tidak ada pola berulang dalam key
        """)
    
    # Contoh Dekripsi
    with st.expander("🔓 Contoh Proses Dekripsi"):
        st.markdown("""
        **Ciphertext:** `ZINCS PVVWO`  
        **Key:** `SECRET`
        
        | Step | CT | n(CT) | K | n(K) | (CT-K)%26 | PT | KeyStream |
        |------|----|----|----|----|-----------|----|----|
        | 1 | Z | 25 | S | 18 | 7 | H | SECRET |
        | 2 | I | 8 | E | 4 | 4 | E | SECRETH |
        | 3 | N | 13 | C | 2 | 11 | L | SECRETHE |
        | 4 | C | 2 | R | 17 | 11 | L | SECRETHEL |
        | 5 | S | 18 | E | 4 | 14 | O | SECRETHELL |
        | 6 | P | 15 | T | 19 | 22 | W | SECRETHELLO |
        | 7 | V | 21 | H | 7 | 14 | O | SECRETHELLOW |
        | 8 | V | 21 | E | 4 | 17 | R | SECRETHELLOWO |
        | 9 | W | 22 | L | 11 | 11 | L | SECRETHELLOWOR |
        | 10 | O | 14 | L | 11 | 3 | D | SECRETHELLOWORL |
        
        **Hasil Plaintext:** `HELLO WORLD`
        
        **Penjelasan:**
        - Dekripsi menggunakan operasi kebalikan: (CT - K) mod 26
        - Setiap karakter yang didekripsi ditambahkan ke keystream
        - Key harus sama persis dengan yang digunakan saat enkripsi
        """)
    
    # Key Recovery Attack
    with st.expander("🔍 Key Recovery Attack (Known-Plaintext Attack)"):
        st.markdown("""
        **Known-Plaintext Attack** adalah metode kriptanalisis di mana penyerang memiliki 
        akses ke plaintext dan ciphertext yang sesuai, lalu mencoba menemukan key.
        
        **Rumus untuk menemukan Key:**
        ```
        K = (CT - PT) mod 26
        ```
        
        **Contoh:**
        - **Plaintext:** `HELLO`
        - **Ciphertext:** `ZINCS`
        
        | PT | n(PT) | CT | n(CT) | (CT-PT)%26 | Key | n(Key) |
        |----|-------|----|-------|------------|-----|--------|
        | H | 7 | Z | 25 | 18 | S | 18 |
        | E | 4 | I | 8 | 4 | E | 4 |
        | L | 11 | N | 13 | 2 | C | 2 |
        | L | 11 | C | 2 | 17 | R | 17 |
        | O | 14 | S | 18 | 4 | E | 4 |
        
        **KeyStream:** `SECRE...`
        
        Dari keystream ini, kita bisa menemukan key asli adalah **"SECRET"** karena 
        setelah key awal, keystream dilanjutkan dengan plaintext (HELLO).
        
        **Algoritma:**
        1. Hitung key untuk setiap posisi: K = (CT - PT) mod 26
        2. Dapatkan keystream lengkap
        3. Cari pola plaintext dalam keystream
        4. Key asli adalah bagian sebelum pola plaintext pertama muncul
        """)
    
    # Implementasi File Biner
    with st.expander("💾 Enkripsi File Biner (File Biner Implementation)"):
        st.markdown("""
        **Implementasi File Biner** mengenkripsi file biner byte-per-byte menggunakan prinsip Autokey Cipher.
        
        **Karakteristik:**
        - ✅ Enkripsi seluruh byte dalam file (termasuk header)
        - ✅ File tidak dapat dibuka sampai didekripsi
        - ✅ Mendukung semua format file (PDF, DOCX, PNG, MP3, dll)
        - ✅ Ukuran file tetap sama setelah enkripsi
        
        **Algoritma Enkripsi:**
        ```python
        def autokeyEncryptBytes(data: bytes, key: str) -> bytes:
            key_bytes = key.encode("utf-8")
            keyStream = bytearray(key_bytes)
            result = bytearray()
            
            for i, b in enumerate(data):
                if i < len(keyStream):
                    k = keyStream[i]
                else:
                    k = keyStream[i % len(key_bytes)]
                
                ct = (b + k) % 256  # Byte: 0-255
                result.append(ct)
                keyStream.append(b)  # Plaintext byte masuk ke keystream
            
            return bytes(result)
        ```
        
        **Algoritma Dekripsi:**
        ```python
        def autokeyDecryptBytes(data: bytes, key: str) -> bytes:
            key_bytes = key.encode("utf-8")
            keyStream = bytearray(key_bytes)
            result = bytearray()
            
            for i, b in enumerate(data):
                if i < len(keyStream):
                    k = keyStream[i]
                else:
                    k = keyStream[i % len(key_bytes)]
                
                pt = (b - k) % 256  # Byte: 0-255
                result.append(pt)
                keyStream.append(pt)  # Plaintext byte masuk ke keystream
            
            return bytes(result)
        ```
        
        **Perbedaan dengan Enkripsi Teks:**
        - Range nilai: 0-255 (byte) vs 0-25 (huruf A-Z)
        - Operasi: mod 256 vs mod 26
        - Input: binary bytes vs text characters
        - Key: UTF-8 encoded bytes vs uppercase letters only
        """)
    
    # Tips Keamanan
    with st.expander("🛡️ Tips Keamanan & Best Practices"):
        st.markdown("""
        **Memilih Key yang Kuat:**
        - ✅ Gunakan key yang panjang (minimal 8 karakter)
        - ✅ Kombinasi huruf besar, kecil, angka, dan simbol
        - ✅ Hindari kata-kata umum atau nama
        - ✅ Jangan gunakan key yang mudah ditebak
        - ✅ Simpan key dengan aman dan rahasia
        
        **Contoh Key:**
        - ❌ Lemah: `SECRET`, `PASSWORD`, `KEY`
        - ✅ Kuat: `Tr0ngK3y!2024`, `MyS3cur3P@ssw0rd`
        
        **Keamanan File:**
        - 🔒 Simpan file terenkripsi di tempat aman
        - 🔒 Backup key di lokasi terpisah dari file terenkripsi
        - 🔒 Jangan share key melalui channel tidak aman
        - 🔒 Gunakan key yang berbeda untuk file berbeda
        
        **Catatan Penting:**
        - ⚠️ Jika key hilang, file tidak dapat didekripsi
        - ⚠️ Autokey Cipher bukan enkripsi modern standar industri
        - ⚠️ Untuk keamanan maksimal, gunakan enkripsi modern (AES-256)
        - ⚠️ Aplikasi ini untuk pembelajaran dan eksperimen
        """)
    
    # FAQ
    with st.expander("❓ Frequently Asked Questions (FAQ)"):
        st.markdown("""
        **Q: Apakah file yang terenkripsi bisa dibuka?**  
        A: Tidak. File yang terenkripsi dengan File Biner implementation tidak dapat dibuka 
        karena header file ikut terenkripsi. File harus didekripsi terlebih dahulu.
        
        **Q: Bagaimana jika saya lupa key?**  
        A: Tanpa key yang benar, file tidak dapat didekripsi. Tidak ada cara untuk 
        recover key yang hilang kecuali menggunakan known-plaintext attack.
        
        **Q: Apakah bisa enkripsi file besar?**  
        A: Ya, aplikasi ini mendukung file berukuran besar. Namun performa tergantung 
        pada spesifikasi komputer Anda.
        
        **Q: Format apa yang didukung?**  
        A: Semua format file didukung: dokumen (PDF, DOCX), gambar (PNG, JPG), 
        video (MP4, AVI), audio (MP3), archive (ZIP, RAR), dan lainnya.
        
        **Q: Apakah aman untuk data sensitif?**  
        A: Autokey Cipher adalah algoritma klasik untuk pembelajaran. Untuk data 
        sensitif, disarankan menggunakan enkripsi modern seperti AES-256.
        
        **Q: Bagaimana cara kerja Find Key?**  
        A: Find Key menggunakan known-plaintext attack. Anda perlu plaintext dan 
        ciphertext yang sesuai untuk menemukan key yang digunakan.
        
        **Q: Ukuran file berubah setelah enkripsi?**  
        A: Tidak. Ukuran file tetap sama karena setiap byte plaintext menghasilkan 
        satu byte ciphertext.
        """)
    
    # Rumus Matematika
    with st.expander("🧮 Rumus Matematika Detail"):
        st.markdown("""
        **Enkripsi Teks:**
        ```
        C = (P + K) mod 26
        
        Di mana:
        - C = Ciphertext character (0-25)
        - P = Plaintext character (0-25)
        - K = Key character (0-25)
        - mod 26 = Modulo 26 (jumlah huruf dalam alfabet)
        ```
        
        **Dekripsi Teks:**
        ```
        P = (C - K) mod 26
        
        Di mana:
        - P = Plaintext character (0-25)
        - C = Ciphertext character (0-25)
        - K = Key character (0-25)
        ```
        
        **Key Recovery:**
        ```
        K = (C - P) mod 26
        
        Di mana:
        - K = Key character (0-25)
        - C = Ciphertext character (0-25)
        - P = Plaintext character (0-25)
        ```
        
        **Enkripsi Biner (File Biner):**
        ```
        C_byte = (P_byte + K_byte) mod 256
        
        Di mana:
        - C_byte = Ciphertext byte (0-255)
        - P_byte = Plaintext byte (0-255)
        - K_byte = Key byte (0-255)
        - mod 256 = Modulo 256 (range byte)
        ```
        
        **Dekripsi Biner (File Biner):**
        ```
        P_byte = (C_byte - K_byte) mod 256
        
        Di mana:
        - P_byte = Plaintext byte (0-255)
        - C_byte = Ciphertext byte (0-255)
        - K_byte = Key byte (0-255)
        ```
        
        **Konversi Karakter ke Angka:**
        ```
        n = ord(char) - ord('A')
        
        Contoh:
        - 'A' → 0
        - 'B' → 1
        - 'Z' → 25
        ```
        
        **Konversi Angka ke Karakter:**
        ```
        char = chr(n + ord('A'))
        
        Contoh:
        - 0 → 'A'
        - 1 → 'B'
        - 25 → 'Z'
        ```
        """)
    
    # Referensi
    with st.expander("📚 Referensi & Sumber Belajar"):
        st.markdown("""
        **Buku:**
        - "Introduction to Cryptography" by Johannes A. Buchmann
        - "Understanding Cryptography" by Christof Paar
        - "The Code Book" by Simon Singh
        
        **Online Resources:**
        - [Wikipedia - Autokey Cipher](https://en.wikipedia.org/wiki/Autokey_cipher)
        - [Crypto Corner - Autokey](https://crypto.interactive-maths.com/autokey-cipher.html)
        - [Practical Cryptography](http://practicalcryptography.com/ciphers/autokey-cipher/)
        
        **Video Tutorials:**
        - YouTube: "Autokey Cipher Explained"
        - Coursera: "Cryptography I" by Stanford
        - Khan Academy: "Journey into cryptography"
        
        **Tools & Practice:**
        - CyberChef (online crypto tool)
        - CrypTool (educational crypto software)
        - dCode.fr (cipher analysis)
        """)

# ======================================================
# FOOTER
# ======================================================
st.markdown("---")
st.markdown("""
    <div style="text-align: center; padding: 2rem; background: rgba(255,255,255,0.9); border-radius: 15px;">
        <h3 style="color: #667eea; margin-bottom: 1rem;">🔐 Autokey Cipher Application</h3>
        <p style="color: #764ba2;">
            Developed for Cryptography Learning & Education<br>
            <em>Teknik Informatika - Universitas Padjadjaran</em>
        </p>
        <p style="color: #888; margin-top: 1rem; font-size: 0.9rem;">
            © 2025 - Built with Streamlit & Python
        </p>
    </div>
""", unsafe_allow_html=True)