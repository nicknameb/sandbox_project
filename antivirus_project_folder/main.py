import tkinter as tk
from tkinter import filedialog, scrolledtext
import threading
import subprocess
import time
import os
import shutil
import sqlite3
import sys
import requests
import traceback
import hashlib

conn = sqlite3.connect('scan_results.db', check_same_thread=False)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS data
             (number INTEGER PRIMARY KEY AUTOINCREMENT,
             app_name TEXT,
             suspicious_signature TEXT, 
             suspicious_registry TEXT, 
             suspicious_hash TEXT, 
             suspicious_connection TEXT)''')
conn.commit()

# Path settings
current_directory = os.path.dirname(os.path.abspath(sys.argv[0]))

LOG_FILE = current_directory + "\\scan_output.txt"
WORK_DIR = current_directory + "\\shared_vm_folder\\secondary_container"
ANTIVIRUS_EXE = current_directory + "\\sandboxcpp.exe"
REGSHOT_DIFF_FILE_ORIGINAL = current_directory + "\\shared_vm_folder\\~res-x64.txt"
REGSHOT_DIFF_FILE = current_directory + "\\snap_result_folder\\~res-x64.txt"
RESULT_FOLDER = current_directory + "\\snap_result_folder\\"
OLD_SNAPSHOT_FOLDER = current_directory + "\\old_snapshot_folder\\"
OLD_SNAP_NAME = "old_snapshot.txt"
TOR_LIST = current_directory + "\\shared_vm_folder\\shared_container\\tor_nodes.txt"
HASH_LIST = current_directory + "\\signatures.txt"

HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

def get_unique_filename(dest_folder, filename):
    name, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename

    while os.path.exists(os.path.join(dest_folder, new_filename)):
        new_filename = f"{name}({counter}){ext}"
        counter += 1

    return new_filename

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()



class AntivirusGUI:
    def __init__(self, master):
        self.master = master
        master.title("Antivirus Scanner")

        with open(LOG_FILE, "w", encoding="utf-8") as f:
            pass

        self.file_path = ""
        self.stop_monitor = False

        self.antivirus_process = None

        self.suspicious_signature_found = tk.BooleanVar(value=False)
        self.suspicious_registry_found = tk.BooleanVar(value=False)
        self.suspicious_tor_connection = tk.BooleanVar(value=False)
        self.suspicious_hash = tk.BooleanVar(value=False)

        status_frame = tk.Frame(master)
        status_frame.pack(anchor="ne", padx=10, pady=5)

        self.signature_checkbox = tk.Checkbutton(
            status_frame, text="Suspicious Signature Detected",
            variable=self.suspicious_signature_found, state="disabled", anchor="w"
        )
        self.signature_checkbox.pack(anchor="e")

        self.registry_checkbox = tk.Checkbutton(
            status_frame, text="Suspicious Registry Change",
            variable=self.suspicious_registry_found, state="disabled", anchor="w"
        )
        self.registry_checkbox.pack(anchor="e")

        self.tor_checkbox = tk.Checkbutton(
            status_frame, text="Connects to Tor",
            variable=self.suspicious_tor_connection, state="disabled", anchor="w"
        )
        self.tor_checkbox.pack(anchor="e")

        self.hash_checkbox = tk.Checkbutton(
            status_frame, text="Suspicious hash signature",
            variable=self.suspicious_hash, state="disabled", anchor="w"
        )
        self.hash_checkbox.pack(anchor="e")

        self.label = tk.Label(master, text="Select an application to scan:")
        self.label.pack()

        self.select_button = tk.Button(master, text="Browse", command=self.select_file)
        self.select_button.pack()

        self.run_button = tk.Button(master, text="Run Scan", command=self.run_scan)
        self.run_button.pack()

        # Text area to display logs with black background and green text
        self.text_output = tk.Text(master, wrap=tk.WORD, width=100, height=30, bg="black", fg="lime")
        self.text_output.pack()

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self.stop_monitor = True

        if self.antivirus_process and self.antivirus_process.poll() is None:
            self.log("[INFO] Terminating antivirus process...")
            self.antivirus_process.terminate()

            try:
                self.antivirus_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.log("[WARN] Antivirus process did not exit gracefully, forcing kill.")
                self.antivirus_process.kill()

        #close db on finish
        conn.close()

        self.master.destroy()
    def select_file(self):
        self.text_output.delete('1.0', tk.END)

        self.file_path = filedialog.askopenfilename(title="Select a file")
        if self.file_path:
            self.log(f"[INFO] Selected file: {self.file_path}")


    def monitor_log(self):
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while not self.stop_monitor:
                    line = f.readline()
                    if "SUSPICIOUS" in line:
                        suspicious_signature = "True"
                        self.suspicious_signature_found.set(True)
                    if "process connects to tor nodes" in line:
                        self.suspicious_tor_connection.set(True)

                    if line:
                        self.append_to_gui(line)
                    else:
                        time.sleep(0.3)
        except Exception as e:
            self.log(f"[ERROR] Log monitoring failed: {e}")


    def append_to_gui(self, text):
        self.text_output.insert(tk.END, text)
        self.text_output.see(tk.END)

    def log(self, msg):
        self.append_to_gui(msg + "\n")



    def scan_registry(self, diff_file):
        if not os.path.isfile(diff_file):
            self.log("[ERROR] Regshot diff file not found.")
            return

        suspicious = []

        with open(diff_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("["):
                    continue


                if "\\run" in line.lower() or "\\runonce" in line.lower():
                    if ":" in line:
                        parts = line.split(":", 1)
                        key = parts[0].strip()
                        value = parts[1].strip().strip('"')
                        name = key.split("\\")[-1]
                        parent = "\\".join(key.split("\\")[:-1])


                        if any(s in value.lower() for s in ["appdata", "startup", "system32\\tasks"]):
                            suspicious.append({"key": parent, "name": name, "value": value})

                            self.suspicious_registry_found.set(True)

        if (not (not suspicious)):
            self.log("\n[INFO] Suspicious Registry Entries:")
        else:
            self.log("no suspicious registry entries found")
        for entry in suspicious:
            self.log(f"Key: {entry['key']} | Name: {entry['name']} | Value: {entry['value']}")

    def generate_tor_list_file(self, tor_list_file):
        url = "https://check.torproject.org/exit-addresses"
        response = requests.get(url)
        if response.status_code == 200:
            with open(tor_list_file, 'w') as f:
                for line in response.text.splitlines():
                    if line.startswith("ExitAddress"):
                        ip = line.split()[1]
                        f.write(ip + "\n")
            self.log(f"Saved Tor IP list to {tor_list_file}")
        else:
            self.log("Failed to download Tor exit node list")


    def compare_hash(self, hash_file, file_to_scan):
        try:
            file_hash = compute_sha256(file_to_scan).lower()

            with open(hash_file, "r", encoding="utf-8", errors="ignore") as f:
                known_hashes = set(line.strip().lower() for line in f if line.strip())

            return file_hash in known_hashes

        except Exception as e:
            print(f"[ERROR] Failed to check file: {e}")
            return False


    def run_scan(self):

        if not self.file_path:
            self.log("[ERROR] No file selected.")
            return

        suspicious_hash = self.compare_hash(HASH_LIST, self.file_path)
        if(suspicious_hash):
            self.log("SUSPICIOUS hash signature detected")
        else:
            self.log("no suspicious hash signature detected")

        copied_path = os.path.join(WORK_DIR, os.path.basename(self.file_path))

        if (not os.path.exists(copied_path)):
            try:
                shutil.copy2(self.file_path, WORK_DIR)
                self.log(f"[INFO] File copied to: {copied_path}")
            except Exception as e:
                self.log(f"[ERROR] Failed to copy file: {e}")
                return
        else:
            self.log(f"file already exists in the working directory: {copied_path}")

        self.generate_tor_list_file(TOR_LIST)

        time.sleep(3)
        self.stop_monitor = False
        threading.Thread(target=self.monitor_log, daemon=True).start()

        threading.Thread(target=self.run_antivirus, args=(copied_path,), daemon=True).start()

    def run_antivirus(self, copied_path):
        try:
            self.antivirus_process = subprocess.Popen(
                [ANTIVIRUS_EXE, copied_path],
                creationflags=0x00000080  # HIGH_PRIORITY_CLASS
            )
            self.antivirus_process.wait()
            self.log("[INFO] Antivirus scan completed.")
        except Exception as e:
            self.log(f"[ERROR] Antivirus failed: {e}")
        finally:
            time.sleep(1)
            self.stop_monitor = True
            time.sleep(1)

            if (not os.path.exists(REGSHOT_DIFF_FILE)):
                try:
                    shutil.move(REGSHOT_DIFF_FILE_ORIGINAL, RESULT_FOLDER)
                    self.log(f"[INFO] File copied to: {REGSHOT_DIFF_FILE}")
                except Exception as e:
                    self.log(f"[ERROR] Failed to move file: {e}")
                    return
            else:
                self.log(f"file already exists in the working directory: {REGSHOT_DIFF_FILE}")

            self.scan_registry(REGSHOT_DIFF_FILE)

            new_name = RESULT_FOLDER + get_unique_filename(OLD_SNAPSHOT_FOLDER, OLD_SNAP_NAME)
            os.rename(REGSHOT_DIFF_FILE, new_name)

            shutil.move(os.path.join(REGSHOT_DIFF_FILE, new_name), OLD_SNAPSHOT_FOLDER)

            c.execute("INSERT INTO data (app_name, suspicious_signature, suspicious_registry, suspicious_hash, suspicious_connection) VALUES (?, ?, ?, ?, ?)", (self.file_path, str(self.suspicious_signature_found.get()), str(self.suspicious_registry_found.get()), str(self.suspicious_hash.get()), str(self.suspicious_tor_connection.get())))
            conn.commit()


if __name__ == "__main__":
    try:
        root = tk.Tk()
        gui = AntivirusGUI(root)
        root.mainloop()
    except Exception:
        with open(LOG_FILE, "w") as f:
            f.write("Unhandled exception:\n")
            traceback.print_exc(file=f)
        input("An error occurred. Press Enter to exit...")