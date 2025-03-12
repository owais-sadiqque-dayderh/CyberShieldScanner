from flask import Flask, request, jsonify, render_template
import os
import hashlib
import requests
import time
import pefile
import yara
from werkzeug.utils import secure_filename
#from pdfminer.high_level import extract_text

app = Flask(__name__)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max upload size
ALLOWED_EXTENSIONS = {'exe', 'docx', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----- VirusTotal Functions -----
VT_API_KEY = '56155beca02aa80823bab7e45a997bd7f2562d21bac8addaf7ec4b6de131146f'  # Replace with your key

def vt_compute_md5(file_path):
    """Compute the MD5 hash of a file."""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def vt_check(file_hash):
    """Check the file hash against VirusTotal."""
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def vt_is_malicious(file_path):
    """
    Check if a file is malicious using VirusTotal.
    Returns a tuple: (verdict, found_flag)
    - verdict: True if malicious, False if clean
    - found_flag: True if the file was found in the API, False otherwise.
    """
    file_hash = vt_compute_md5(file_path)
    print(f"VirusTotal MD5: {file_hash}")
    result = vt_check(file_hash)
    if result and result.get('data'):
        attributes = result['data']['attributes']
        if attributes['last_analysis_stats']['malicious'] > 0:
            print("VirusTotal: Malicious file detected!")
            return True, True
        else:
            print("VirusTotal: File is clean.")
            return False, True
    else:
        print("VirusTotal: File not found in VirusTotal database or API error.")
        return None, False

# ----- Hybrid Analysis Functions -----
HA_API_KEY = 'zreoceycdb78f9f71rsjel869a3cb425k33v513s96b9971fm3w2bpyf63806d75'  # Replace with your key

def ha_compute_sha256(file_path):
    """Compute the SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def ha_check(file_hash):
    """Check the file hash against Hybrid Analysis."""
    url = f'https://www.hybrid-analysis.com/api/v2/report/{file_hash}/summary'
    headers = {
        'api-key': HA_API_KEY,
        'user-agent': 'Falcon Sandbox'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def ha_is_malicious(file_path):
    """
    Check if a file is malicious using Hybrid Analysis.
    Returns a tuple: (verdict, found_flag)
    - verdict: True if malicious, False if clean
    - found_flag: True if the file was found in the API, False otherwise.
    """
    file_hash = ha_compute_sha256(file_path)
    print(f"Hybrid Analysis SHA-256: {file_hash}")
    result = ha_check(file_hash)
    if result:
        verdict = result.get('verdict')
        if verdict == 'malicious':
            print("Hybrid Analysis: Malicious file detected!")
            return True, True
        else:
            print("Hybrid Analysis: File is clean.")
            return False, True
    else:
        print("Hybrid Analysis: File not found in Hybrid Analysis database or API error.")
        return None, False

# ----- YARA / Main Analysis Functions (from original app.py) -----
def compile_yara_rules(rules_directory='rules'):
    rule_files = {}
    for root, dirs, files in os.walk(rules_directory):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                namespace = os.path.splitext(file)[0]
                rule_files[namespace] = os.path.join(root, file)
    return yara.compile(filepaths=rule_files, externals={'filename': '', 'filepath': '', 'extension': '', 'filetype': '','is__elf': 0})

rules = compile_yara_rules('rules')

def get_filetype(ext):
    mapping = {
        'exe': 'EXE',
        'docx': 'DOCX',
        'pdf': 'PDF',
        'jpg': 'JPEG',
        'jpeg': 'JPEG'
    }
    return mapping.get(ext, '')

def is_elf(filepath):
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except Exception:
        return False

def extract_pdf_text(filepath):
    try:
        text = extract_text(filepath)
        return text.lower()
    except Exception as e:
        print(f"Error extracting PDF text: {e}")
        return ""

def analyze_file(filepath, ext):
    verdict = "Clean"
    risk_report = []

    # YARA Analysis
    try:
        matches = rules.match(filepath, externals={
            'filename': os.path.basename(filepath),
            'filepath': os.path.abspath(filepath),
            'extension': ext,
            'filetype': get_filetype(ext),
            'is__elf': 1 if is_elf(filepath) else 0
        })
        if matches:
            verdict = "Malicious"
            matched_rules = ', '.join(match.rule for match in matches)
            risk_report.append(f"YARA match: {matched_rules}")
    except Exception as e:
        risk_report.append("Error during YARA scan: " + str(e))

    # PE Analysis for .exe files
    if ext == 'exe':
        try:
            pe = pefile.PE(filepath)
            for section in pe.sections:
                entropy = section.get_entropy()
                if entropy > 7.6:
                    verdict = "Malicious"
                    section_name = section.Name.decode(errors="ignore").strip()
                    risk_report.append(f"High entropy ({entropy:.2f}) in section '{section_name}'")
        except Exception as e:
            risk_report.append("Error parsing PE file: " + str(e))

    # Keyword Analysis for .docx and .pdf files
    if ext in ['docx', 'pdf']:
        try:
            with open(filepath, 'rb') as f:
                content = f.read().lower()
                if b"macro" in content or b"eval(" in content:
                    verdict = "Malicious"
                    risk_report.append("Suspicious keyword detected (e.g., 'macro' or 'eval(')")
        except Exception as e:
            risk_report.append("Error reading file content: " + str(e))
        if ext == 'pdf':
            try:
                text = extract_pdf_text(filepath)
                if "macro" in text or "eval(" in text:
                    verdict = "Malicious"
                    risk_report.append("Suspicious keyword detected in PDF (e.g., 'macro' or 'eval(')")
            except Exception as e:
                risk_report.append("Error processing PDF content: " + str(e))

    return verdict, risk_report

# ----- Flask Routes -----
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        ext = filename.rsplit('.', 1)[1].lower()

        # Step 1: VirusTotal check
        vt_verdict, vt_found = vt_is_malicious(filepath)
        if vt_found:
            os.remove(filepath)
            if vt_verdict:
                return jsonify({
                    'verdict': 'Malicious',
                    'risk_report': ['Hashing detected malicious file']
                }), 200
            else:
                return jsonify({
                    'verdict': 'Clean',
                    'risk_report': ['Hashing indicates file is clean']
                }), 200

        # Step 2: If VirusTotal did not return a result, try Hybrid Analysis
        ha_verdict, ha_found = ha_is_malicious(filepath)
        if ha_found:
            os.remove(filepath)
            if ha_verdict:
                return jsonify({
                    'verdict': 'Malicious',
                    'risk_report': ['Hashing detected malicious file']
                }), 200
            else:
                return jsonify({
                    'verdict': 'Clean',
                    'risk_report': ['Hashing indicates file is clean']
                }), 200

        # Step 3: If neither API returned a result, run internal analysis.
        verdict, risk_report = analyze_file(filepath, ext)
        os.remove(filepath)
        return jsonify({
            'verdict': verdict,
            'risk_report': risk_report
        }), 200

    return jsonify({'error': 'File type not allowed'}), 400

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, port=9999)
