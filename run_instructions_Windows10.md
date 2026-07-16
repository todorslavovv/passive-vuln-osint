# Run Instructions: Windows 10

Open PowerShell in:

```powershell
cd C:\DOWNLOADS\Projects\OSINT_Project
```

## Install

No required third-party dependencies are needed.

Optional editable install:

```powershell
python -m pip install -e .
```

Without installing, run the package directly with `python -m osintdepintel`.

## Run All Sample Targets Offline

```powershell
python -m osintdepintel --config examples\targets.json --all --offline --output-dir reports
```

## Run One Target Offline

```powershell
python -m osintdepintel --config examples\targets.json --target juice-shop --offline --output-dir reports
```

## Run Live Passive Mode

```powershell
python -m osintdepintel --config examples\targets.json --target juice-shop --output-dir reports
```

Live mode only uses passive public sources. It does not scan ports, brute force, exploit, or actively probe vulnerabilities.

## Run Tests

```powershell
python -m unittest discover -s tests
```

## Sample Configuration

The sample target configuration is:

```text
examples\targets.json
```

Reports are written to:

```text
reports\
```

A virtual environment is optional. If you prefer one:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```
