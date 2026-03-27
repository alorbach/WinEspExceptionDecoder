@echo off
setlocal

set "ROOT=%~dp0."
if not exist "%ROOT%\.venv\Scripts\python.exe" (
  echo Virtual environment not found. Run setup.bat first.
  exit /b 1
)

call "%ROOT%\.venv\Scripts\activate.bat" || exit /b 1
python -m winespexceptiondecoder
