
# CyberShield Scanner

This project is a malware scanner web application built with a Flask backend and an HTML/CSS/JavaScript frontend. Users can upload files to be scanned for malicious indicators. This is done by using , Hashing API ,YARA rules, PE analysis, and entropy measurement The app features a stylish interface with a loading bar and returns a detailed verdict and risk report in JSON format.




## Authors

- [@Ekansh2406](https://github.com/Ekansh2406)
- [@PotatoORG](https://github.com/PotatoORG)
- [@Harsh Anand](https://www.linkedin.com/in/harsh-anand-iitm/)
- [@Owais-Sadiqque-Dayderh](https://github.com/owais-sadiqque-dayderh)




## Deployment

First clone this repository using git

```bash
git clone https://github.com/Ekansh2406/bluepill.git
```

Then you have to activate the virtual environment by the following command inside the repository

```bash
source venv/bin/activate
```

Then jump to running the script. If it shows "nodes not found" , install the following python modules

```bash
sudo apt install pyhton3-flask python3-pefile python3-pdfminor
```

Inside the CyberShieldScanner/CyberShieldScanner ,run 

```bash
python3 app.py
```

And At Last Finally Open the link shown in terminal in web browser and now No Malware Can Enter your Device.
## Features

This Python code builds a Flask web app that accepts file uploads for malware detection.

It restricts uploads to certain file types (.exe, .docx, .pdf) and limits file size to 100 MB.

When a file is uploaded, it’s securely saved and its extension is verified.

The app computes file hashes (MD5 for VirusTotal and SHA-256 for Hybrid Analysis) to check against external malware databases.

It uses VirusTotal’s API to determine if the file is known to be malicious; if so, the file is deleted and a “Malicious” verdict is returned.

If VirusTotal doesn’t yield a result, the app checks the file with Hybrid Analysis’s API.

Should both API checks fail to flag the file, the program runs an internal analysis using YARA rules to spot suspicious patterns.

For executable files, it performs additional PE analysis by checking section entropy to uncover potential threats.

Document and PDF files are scanned for suspicious keywords, and PDF text is extracted for further examination.

The final verdict—either “Clean” or “Malicious”—is returned in a JSON response along with a risk report detailing any findings.

After analysis, the uploaded file is removed to maintain security.

## Warnings

Might not work on WINDOWS.

Will not work if API's limit is exceeded.
