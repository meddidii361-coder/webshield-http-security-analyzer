# WebShield — HTTP Security Headers Analyzer

WebShield is a local-first Python web application for reviewing HTTP security headers. It reuses the original scanner, analyzer, and report generator, and adds a Flask dashboard, scan history (SQLite), and TXT/JSON exports.

## Features
- Premium dark cybersecurity dashboard
- HTTP security header analysis and weighted score
- PASS / WARN / FAIL findings with recommendations
- Scan history stored locally in SQLite
- TXT and JSON report downloads; browser Print can save a PDF
- Existing command-line interface remains available

## Requirements
- Windows 10/11
- Python 3.10 or newer
- VS Code (optional)

## Run on Windows (PowerShell)

Open the project folder in VS Code and choose **Terminal → New Terminal**.

If your prompt already starts with `(.venv)`, skip the environment creation and activation steps.

```powershell
# Create a virtual environment (only once)
python -m venv .venv

# If PowerShell blocks activation, allow scripts for this terminal only:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate the environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install -r requirements.txt

# Start the dashboard
python app.py
```

Open this address in your browser:

`http://127.0.0.1:5000`

Keep the terminal running while using the dashboard. Press `Ctrl+C` in the terminal to stop it.

### If `python` is not recognized
Use the Python interpreter selected by VS Code. Open **View → Command Palette**, run **Python: Select Interpreter**, and select the Python installation. If you already created `.venv`, select the interpreter at `.venv\Scripts\python.exe`. Then open a new terminal and run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

If you have not created `.venv` yet and your Python executable is managed by `uv`, create the environment using the exact interpreter path shown by `print(sys.executable)` in the VS Code Python terminal:

```powershell
& "PASTE-THE-python.exe-PATH-HERE" -m venv .venv
```

Then use `.venv\Scripts\python.exe` for installation and launch as above. This avoids installing packages into an externally managed Python installation.

## Use
1. Enter a full URL, such as `https://example.com`.
2. Click **Scan website**.
3. Review the score and individual header findings.
4. Download TXT/JSON reports or use **Print / PDF** in your browser.
5. Open **Scan history** to revisit previous scans.

The CLI is still available:

```powershell
python webshield.py https://example.com
python webshield.py https://example.com --format json
python -m unittest discover -s tests -v
```

## Safety and limitations
- Only scan websites you own or have explicit permission to assess.
- The scanner sends one ordinary HTTP GET request and follows redirects.
- This is a passive HTTP response-header configuration review, not a penetration test.
- A missing header does not by itself prove that a site is exploitable.
- The Flask development server binds to `127.0.0.1` only. Do not expose it to the public internet as-is.
- This project is intended for local portfolio and learning use, not production deployment.

## Project structure

```text
webshield/
├── app.py
├── webshield.py
├── scanner.py
├── analyzer.py
├── reporter.py
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/app.js
├── data/                 # local SQLite history (created automatically)
├── reports/
└── tests/
```
