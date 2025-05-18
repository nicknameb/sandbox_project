import socket
import time

tor_ip = "1.170.206.200"   #this is a tor EXIT node, so it might not a;ways respond
tor_port = 443             #but testing otherwise will require tor installation

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((tor_ip, tor_port))
    print(f"Successfully connected to Tor node at {tor_ip}:{tor_port}")

    time.sleep(20)
    s.close()
except Exception as e:
    print(f"Connection failed: {e}")