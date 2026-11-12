@echo off
cd /d "C:\Users\anous\OneDrive\Desktop\nemesis"
set PYTHONPATH=.
start /B /WAIT python backend/http_boya_service.py
timeout /t 3 /nobreak >nul
python -c "import socket,sys; s=socket.socket(); s.settimeout(2);
try:
    s.connect(('127.0.0.1',11643))
    s.close()
    print('BYOA server on port 11643: OPEN')
except Exception as e:
    print(f'Port 11643: {e}')
    sys.exit(1)
"