# Lab Programs 6, 7 & 8 – Streamlit demos

lab_programs/
├── requirements.txt              (shared by all three)
├── Q6_secure_messaging_e2ee/     TLS + End-to-End Encryption chat, architecture + sequence diagram
├── Q7_hashing_obfuscation/       hashlib hashes + Python obfuscator
└── Q8_signatures_auth_jwt/       RSA signatures + Flask/JWT auth + banking case study

## Step-by-step (VS Code)
1. Unzip and open the `lab_programs` folder: File > Open Folder.
2. Open the terminal: Ctrl+` (backtick).
3. Create the virtual environment (once):
   - Windows:      python -m venv venv
   - macOS/Linux:  python3 -m venv venv
4. Activate it:
   - Windows PowerShell: .\venv\Scripts\Activate.ps1   (if blocked: Set-ExecutionPolicy -Scope Process Bypass)
   - Windows CMD:        venv\Scripts\activate.bat
   - macOS/Linux:        source venv/bin/activate
5. Install dependencies (once):  pip install -r requirements.txt
6. In VS Code press Ctrl+Shift+P > "Python: Select Interpreter" > choose the ./venv one.
7. Run ONE app at a time (each opens in the browser):
   streamlit run Q6_secure_messaging_e2ee/app.py
   streamlit run Q7_hashing_obfuscation/app.py
   streamlit run Q8_signatures_auth_jwt/app.py
   Stop with Ctrl+C. To run two at once, add --server.port 8502 to the second command.

Ports used internally: Q6 TLS relay 8443, Q8 Flask API 5008 (close the other Q6/Q8 run if "address in use").
Demo logins for Q8: alice/alice123, bob/bob123, admin/admin123.
