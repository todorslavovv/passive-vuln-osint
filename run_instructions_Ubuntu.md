# Run Instructions: Ubuntu

Open a terminal in the project directory:

```bash
cd /path/to/OSINT_Project
```

## Install

No required third-party dependencies are needed.

Optional editable install:

```bash
python3 -m pip install -e .
```

Without installing, run the package directly with `python3 -m osintdepintel`.

## Run All Sample Targets Offline

```bash
python3 -m osintdepintel --config examples/targets.json --all --offline --output-dir reports
```

## Run One Target Offline

```bash
python3 -m osintdepintel --config examples/targets.json --target juice-shop --offline --output-dir reports
```

## Run Live Passive Mode

```bash
python3 -m osintdepintel --config examples/targets.json --target juice-shop --output-dir reports
```

Live mode only uses passive public sources. It does not scan ports, brute force, exploit, or actively probe vulnerabilities.

## Run Tests

```bash
python3 -m unittest discover -s tests
```

## Sample Configuration

The sample target configuration is:

```text
examples/targets.json
```

Reports are written to:

```text
reports/
```

A virtual environment is optional. If you prefer one:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```
