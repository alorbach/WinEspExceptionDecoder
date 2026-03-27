@echo off
setlocal

set "ROOT=%~dp0."
if not exist "%ROOT%\.venv\Scripts\python.exe" (
  python -m venv "%ROOT%\.venv" || exit /b 1
)

call "%ROOT%\.venv\Scripts\activate.bat" || exit /b 1
python -m pip install --upgrade pip || exit /b 1
python -m pip install -e "%ROOT%" || exit /b 1

echo Setup complete.
