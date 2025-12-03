ui_styling = """
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
    div[data-testid="stExpander"] {
        background: rgba(255, 255, 255, 0.85);
        border-radius: 15px;
        border: 2px solid #cfe3ff;
        box-shadow: 0 4px 14px rgba(164, 198, 255, 0.3);
    }

    [data-testid="stExpander"] span[data-testid="stIconMaterial"] {
        display: none !important;
        visibility: hidden !important;
    }

    /* PREVIEW BOX ================================================== */
    .preview-box {
        background: rgba(255, 255, 255, 0.9);
        padding: 1rem;
        border-radius: 12px;
        border-left: 5px solid #7ba7ff;
        margin: 1rem 0;
    }

    /* SIDEBAR ====================================================== */
    button[data-testid="stExpandSidebarButton"] span[data-testid="stIconMaterial"] {
        display: none !important;
    }
    
    button[data-testid="stExpandSidebarButton"] {
        position: relative !important;
        min-width: 44px !important;
        min-height: 44px !important;
        background: rgba(255, 255, 255, 0.9) !important;
        border-radius: 50% !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1) !important;
        transition: all 0.3s ease !important;
    }
    
    button[data-testid="stExpandSidebarButton"]:hover {
        background: white !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15) !important;
        transform: scale(1.05) !important;
    }

    button[data-testid="stExpandSidebarButton"]::before {
        content: "›" !important;
        font-size: 1.8rem !important;
        font-weight: bold !important;
        display: inline-block !important;
        color: #ff9ac9 !important;
        position: absolute !important;
        top: 50% !important;
        left: 50% !important;
        transform: translate(-50%, -50%) rotate(0deg) !important;
        transition: transform 0.3s ease !important;
    }

    .st-emotion-cache-pd6qx2,
    .ejhh0er0 {
        display: none !important;
    }
    """

header = """
    <div class="main-header">
        <h1>🔐 Autokey Cipher</h1>
        <p>Advanced Cryptography Application - Complete File Encryption System</p>
    </div>
"""

enkripsi_file_biner = """
    <div class="info-card">
        <h3>🔒 Enkripsi File Biner - Implementasi File Biner</h3>
        <p>Fitur ini mengenkripsi <strong>seluruh byte dalam file</strong>, termasuk header. 
        File yang terenkripsi tidak akan bisa dibuka sampai didekripsi kembali dengan key yang benar.</p>
        <p><strong>Mendukung:</strong> PDF, DOCX, XLSX, PNG, JPG, MP3, MP4, ZIP, dan semua format file!</p>
    </div>
"""

file_details_card = """
<div>
    <span style='font-size:16px'>{label}</span><br>
    <span style='font-size:22px'>{value}</span><br><br>
</div>
"""

key_recovery = """
    <div class="info-card">
        <h3>🔍 Key Recovery Attack</h3>
        <p>Fitur ini memungkinkan Anda menemukan key yang digunakan untuk enkripsi 
        jika Anda memiliki plaintext dan ciphertext yang sesuai.</p>
        <p><strong>Catatan:</strong> Ini adalah serangan kriptanalisis known-plaintext attack.</p>
    </div>
"""

panduan = """
    <div class="info-card">
        <h3>📖 Panduan Lengkap Autokey Cipher</h3>
    </div>
"""

footer = """
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
"""