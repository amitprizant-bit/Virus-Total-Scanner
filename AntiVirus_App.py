import hashlib
import os
from pathlib import Path
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk

import pyglet
import vt

VT_API_KEY = "ENTER_YOUR_API_KEY"

scan_results = []


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a local file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def scan_file(client, file_path):
    print(f"\nScanning: {file_path.name}")
    try:
        file_hash = calculate_sha256(file_path)
        if not file_hash:
            raise Exception("Could not compute hash")

        # Step 1: Check if VT already knows this file via SHA-256 (Instant)
        try:
            vt_file = client.get_object(f"/files/{file_hash}")
            stats = vt_file.last_analysis_stats
        except vt.APIError as err:
            # Step 2: File unknown to VT (404) -> Fall back to uploading it
            if err.code == "NotFoundError":
                with open(file_path, "rb") as f:
                    analysis = client.scan_file(f)

                while True:
                    time.sleep(15)  # Pace queries to avoid rate limits
                    analysis = client.get_object(f"/analyses/{analysis.id}")
                    if analysis.status == "completed":
                        break

                stats = analysis.stats
            else:
                raise err

        if stats.get("malicious", 0) > 0:
            status = "Malicious"
        elif stats.get("suspicious", 0) > 0:
            status = "Suspicious"
        else:
            status = "Clean"

        scan_results.append(
            {
                "file": file_path.name,
                "status": status,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }
        )

        # Pause to respect the Free Tier limit (4 requests/min = ~15s per request)
        time.sleep(15)

    except Exception as e:
        print(f"Error scanning {file_path.name}: {e}")
        scan_results.append(
            {
                "file": file_path.name,
                "status": "Error",
                "malicious": "-",
                "suspicious": "-",
                "undetected": "-",
            }
        )


def iterate_folder(client, folder_path):
    path = Path(folder_path)
    if not path.exists():
        return

    for item in path.iterdir():
        if item.is_file():
            scan_file(client, item)
            root.after(0, my_progress_bar.step, 1)
        elif item.is_dir():
            iterate_folder(client, item)


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


def thread_scan_worker(folder_path):
    global scan_results
    scan_results = []

    total_files = count_files(folder_path)
    if total_files == 0:
        root.after(0, label.config, {"text": "No files found in folder."})
        return

    root.after(0, setup_progressbar, total_files)

    local_client = vt.Client(VT_API_KEY)
    try:
        iterate_folder(local_client, folder_path)
    finally:
        local_client.close()
        root.after(0, final_ui)


def start_scan_workflow():
    chosen_path = filedialog.askdirectory(
        title="Select a Folder to Scan", initialdir="/"
    )
    if chosen_path:
        label.config(text=f"Scanning:\n{chosen_path}")
        for item in results_tree.get_children():
            results_tree.delete(item)
        results_frame.pack_forget()

        scan_thread = threading.Thread(
            target=thread_scan_worker, args=(chosen_path,), daemon=True
        )
        scan_thread.start()


def setup_progressbar(total_files):
    my_progress_bar.pack(pady=15)
    my_progress_bar["maximum"] = total_files
    my_progress_bar["value"] = 0
    button.config(state=tk.DISABLED)


def final_ui():
    label.config(text="Scan Complete!")
    button.config(state=tk.NORMAL)

    for result in scan_results:
        tag = result["status"].lower()
        results_tree.insert(
            "",
            tk.END,
            values=(
                result["file"],
                result["status"],
                result["malicious"],
                result["suspicious"],
                result["undetected"],
            ),
            tags=(tag,),
        )

    results_frame.pack(pady=20, padx=40, fill="both", expand=True)


# --- GUI INITIALIZATION ---
custom_font = pyglet.font.add_file(
    r"C:\Users\amitp\VSCode\AntiVirus\BlackOpsOne-Regular.ttf"
)
root = tk.Tk()
root.title("AntiVirus Scanner")
root.configure(background="#080928")
root.geometry("1080x720")

# --- STYLING TREEVIEW & PROGRESSBAR ---
style = ttk.Style()
style.theme_use("default")

style.configure(
    "Treeview",
    background="#12143E",
    foreground="#FFFFFF",
    rowheight=32,
    fieldbackground="#12143E",
    bordercolor="#080928",
    borderwidth=0,
    font=("Segoe UI", 10),
)

style.configure(
    "Treeview.Heading",
    background="#1B1E56",
    foreground="#4E54C8",
    relief="flat",
    font=("Segoe UI", 11, "bold"),
    padding=8,
)

style.map("Treeview.Heading", background=[("active", "#252974")])

style.configure(
    "Horizontal.TProgressbar",
    thickness=12,
    troughcolor="#12143E",
    background="#4E54C8",
)

label = tk.Label(
    root,
    text="AntiVirus Scanner",
    font=(custom_font, 22),
    fg="#a8aebf",
    background="#080928",
    pady=20,
)
label.pack()

button_frame = tk.Frame(root, bg="#080928")
button_frame.pack(pady=5)

button = tk.Button(
    button_frame,
    text="Select & Scan Folder",
    font=(custom_font, 12),
    command=start_scan_workflow,
    fg="#080928",
    bg="#4E54C8",
    activebackground="#6066DF",
    activeforeground="#080928",
    bd=0,
    relief="flat",
    padx=25,
    pady=12,
    cursor="hand2",
)
button.pack()

my_progress_bar = ttk.Progressbar(
    root,
    orient="horizontal",
    length=500,
    mode="determinate",
    style="Horizontal.TProgressbar",
)

results_frame = tk.Frame(root, bg="#080928")

columns = ("file", "status", "malicious", "suspicious", "undetected")
results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=10)

results_tree.tag_configure("malicious", foreground="#FF4D4D", background="#2A121A")
results_tree.tag_configure("suspicious", foreground="#FFB84D", background="#2A2212")
results_tree.tag_configure("clean", foreground="#4DFF88", background="#122A1E")
results_tree.tag_configure("error", foreground="#A0A0A0", background="#1E1E1E")

results_tree.heading("file", text="File Name")
results_tree.heading("status", text="Verdict")
results_tree.heading("malicious", text="Malicious")
results_tree.heading("suspicious", text="Suspicious")
results_tree.heading("undetected", text="Clean")

results_tree.column("file", width=380, anchor="w")
results_tree.column("status", width=120, anchor="center")
results_tree.column("malicious", width=100, anchor="center")
results_tree.column("suspicious", width=100, anchor="center")
results_tree.column("undetected", width=100, anchor="center")

scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_tree.yview)
results_tree.configure(yscrollcommand=scrollbar.set)

results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


def on_closing():
    root.destroy()


root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
