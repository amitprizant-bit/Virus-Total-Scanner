import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk
import vt

VT_API_KEY = "60b6b5a671c1b314dc696c090dc0b1492ad2313cae9c10ae095473c7d2d87727"


def scan_file(client, file_path):
    print(f"\nScanning: {file_path.name}")
    try:
        with open(file_path, "rb") as f:
            analysis = client.scan_file(f)

        print(f"File uploaded successfully. Analysis ID: {analysis.id}")
        print("Waiting for analysis to complete...", end="", flush=True)

        while True:
            analysis = client.get_object(f"/analyses/{analysis.id}")
            if analysis.status == "completed":
                print(" Done!")
                break
            print(".", end="", flush=True)
            time.sleep(5)

        stats = analysis.stats
        print(f"Results for {file_path.name}:")

        mal_warn = " --> WARNING, FILE IS MALICIOUS!" if stats["malicious"] > 0 else ""
        susp_warn = (
            " --> WARNING, FILE IS SUSPICIOUS!" if stats["suspicious"] > 0 else ""
        )
        clean_msg = " --> Clean file, no threats." if stats["malicious"] == 0 else ""

        print(f" - Malicious: {stats['malicious']}{mal_warn}")
        print(f" - Suspicious: {stats['suspicious']}{susp_warn}")
        print(f" - Undetected/Clean: {stats['undetected']}{clean_msg}")

    except Exception as e:
        print(f"Error scanning {file_path.name}: {e}")


def iterate_folder(client, folder_path):
    path = Path(folder_path)
    if not path.exists():
        print("The specified path does not exist.")
        return

    for item in path.iterdir():
        if item.is_file():
            scan_file(client, item)
            # Safely step the progress bar forward by 1 on the GUI thread
            root.after(0, my_progress_bar.step, 1)
        elif item.is_dir():
            iterate_folder(client, item)


def thread_scan_worker(folder_path):
    total_files = count_files(folder_path)
    if total_files == 0:
        print("Nothing To Scan")
        root.after(0, label.config, {"text": "No files in the folder."})
        return

    # Fixed syntax to pass the function object safely
    root.after(0, setup_progressbar, total_files)

    local_client = vt.Client(VT_API_KEY)
    try:
        iterate_folder(local_client, folder_path)
    finally:
        local_client.close()
        print("\n--- Scan completed. Connection closed gracefully. ---")
        root.after(0, final_ui)


def count_files(folder_path):
    path = Path(folder_path)
    count = 0
    if not path.exists():
        return 0
    for item in path.iterdir():
        if item.is_file():
            count += 1
        elif item.is_dir():
            count += count_files(item)
    return count


# Renamed function to prevent variable masking
def setup_progressbar(total_files):
    my_progress_bar.pack(pady=10)
    my_progress_bar["maximum"] = total_files
    my_progress_bar["value"] = 0
    button.config(state=tk.DISABLED)


def final_ui():
    label.config(text="Scan Complete!")
    button.config(state=tk.NORMAL)


def start_scan_workflow():
    chosen_path = filedialog.askdirectory(
        title="Select a Folder to Scan", initialdir="/"
    )

    if chosen_path:
        print(f"Selected folder: {chosen_path}")
        label.config(
            text=f"Scanning:\n{chosen_path}\nCheck terminal for live progress..."
        )

        scan_thread = threading.Thread(
            target=thread_scan_worker, args=(chosen_path,), daemon=True
        )
        scan_thread.start()


root = tk.Tk()
root.title("AntiVirus Scanner")
root.configure(background="Light Blue")
root.geometry("700x700")

label = tk.Label(
    root,
    text="AntiVirus, Click the button to scan.",
    font=("Arial", 12),
    background="Light Yellow",
)
label.pack(pady=40)

button = tk.Button(
    root,
    text="Select & Scan Folder",
    command=start_scan_workflow,
    padx=10,
    pady=5,
    background="Light Yellow",
)
button.pack()

my_progress_bar = ttk.Progressbar(
    root,
    orient="horizontal",
    length=300,  # Extended width slightly so it looks proportional on a 700x700 canvas
    mode="determinate",
)


def on_closing():
    root.destroy()


root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
