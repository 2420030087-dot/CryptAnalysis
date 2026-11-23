import os
import sys
import socket
import webbrowser
import threading
import time
import uvicorn

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

BANNER = r"""
======================================================================
  ______ _____ _      ______  _____ _    _ _____ ______ _      _____  
 |  ____|_   _| |    |  ____|/ ____| |  | |_   _|  ____| |    |  __ \ 
 | |__    | | | |    | |__  | (___ | |__| | | | | |__  | |    | |  | |
 |  __|   | | | |    |  __|  \___ \|  __  | | | |  __| | |    | |  | |
 | |     _| |_| |____| |____ ____) | |  | |_| |_| |____| |____| |__| |
 |_|    |_____|______|______|_____/|_|  |_|_____|______|______|_____/ 

          Real-Time File Integrity & AI Anomaly Detection System
======================================================================
 [*] Host Protection: ACTIVE
 [*] Cryptographic Engine: SHA-256 Trusted Fingerprints
 [*] AI Engine: Temporal Pattern & Behavioral Anomaly Detection
 [*] Monitored Path: ./protected_files
======================================================================
"""

def find_available_port(default_port: int = 8000) -> int:
    for port in range(default_port, default_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return default_port

def open_browser(port: int):
    time.sleep(1.2)
    webbrowser.open(f"http://127.0.0.1:{port}")

if __name__ == "__main__":
    print(BANNER)
    port = find_available_port(8000)
    if port != 8000:
        print(f" [!] Note: Port 8000 was busy. Running FileShield on port {port}.")
    print(f" [*] Web Dashboard: http://127.0.0.1:{port}\n======================================================================\n")

    # Automatically open the browser
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    
    # Run FastAPI via Uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=port, reload=False, log_level="info")

