# WebSec Scanner

Lightweight, non-destructive web security scanner. Checks common HTTP security headers, gathers basic SSL/TLS info, performs a safe directory probe, and generates a Markdown report (`report.md`).

## Quick start (Windows / PowerShell)

1. Open PowerShell and go to the project folder:
```powershell
cd C:\websec_scanner
```

2. Create & activate a virtual environment (if not already present):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

3. Upgrade pip and install dependencies:
```powershell
python -m pip install --upgrade pip
python -m pip install requests beautifulsoup4
# or install from requirements.txt:
python -m pip install -r .\requirements.txt
```

Note: if `pip install -r requirements.txt` fails with a pinned `certifi` version (e.g. `certifi==2024.11.1`), relax the pin before reinstalling:
```powershell
(Get-Content .\requirements.txt) -replace 'certifi==2024.11.1','certifi>=2024.12.14' | Set-Content .\requirements.txt
python -m pip install -r .\requirements.txt
```

4. Run the scanner:
```powershell
# with venv active
python .\scanner.py https://example.com

# or explicitly using the venv interpreter
& 'C:\websec_scanner\venv\Scripts\python.exe' 'C:\websec_scanner\scanner.py' https://example.com
```

5. Open the generated report:
```powershell
notepad .\report.md
# or in VS Code:
code .\report.md
```

## Troubleshooting (common issues)

- ModuleNotFoundError: No module named 'requests'
  - Ensure the venv is active and `requests` is installed (see step 3).

- pip error: Could not find a version that satisfies the requirement certifi==...
  - Edit `requirements.txt` to remove/relax the strict `certifi` pin, or install a valid version manually:
    ```powershell
    python -m pip install certifi==2024.12.14
    ```

- PowerShell suggestion about `report.md` not found
  - PowerShell treats plain filenames as commands. To open/view files in the current directory prefix with `./` or `.\
  - Example: `notepad .\report.md`, `Get-Content .\report.md`, or `code .\report.md`.

## Usage notes

- This tool is intentionally non-destructive. Only run it against targets you are authorized to test.
- For deeper testing use professional tools and an authorized test plan.

## Contributing

Contributions welcome — open an issue or submit a pull request. Keep changes small and testable.

## License

Add your preferred license here.
