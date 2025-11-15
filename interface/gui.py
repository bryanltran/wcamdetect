import tkinter as tk
from tkinter import filedialog, messagebox

class PacketApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Camera Detection - GUI")
        self.root.geometry("520x260")

        self.title_label = tk.Label(
            root, text="WiFi Camera Detection",
            font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=10)

        self.file_label = tk.Label(root, text="No file loaded.", fg="gray")
        self.file_label.pack(pady=5)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=8)

        self.load_button = tk.Button(
            btn_frame, text="Load PCAP File",
            command=self.load_pcap,
            width=18
        )
        self.load_button.grid(row=0, column=0, padx=8, pady=4)

        self.analyze_button = tk.Button(
            btn_frame, text="Run Analysis",
            command=self.run_analysis,
            width=18
        )
        self.analyze_button.grid(row=0, column=1, padx=8, pady=4)

        self.info_text = tk.Text(root, height=6, width=60)
        self.info_text.pack(pady=8)
        self.info_text.insert("1.0", "Load a .pcap file to see basic info.\n")
        self.info_text.configure(state="disabled")

    def load_pcap(self):
        file_path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*"))
        )
        if file_path:
            self.file_label.config(text=f"Loaded: {file_path}", fg="black")
            self.loaded_file = file_path
            self._show_info(f"File loaded:\n{file_path}")

    def run_analysis(self):
        if hasattr(self, "loaded_file"):
            self._show_info("Analysis would run here.\n(Not implemented yet.)")
            messagebox.showinfo("Analysis", "Placeholder analysis ran.")
        else:
            messagebox.showwarning("No File", "Please load a PCAP file first.")

    def _show_info(self, text):
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", text)
        self.info_text.configure(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketApp(root)
    root.mainloop()
