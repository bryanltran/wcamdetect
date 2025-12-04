import tkinter as tk
from tkinter import filedialog, messagebox
import sys
from pathlib import Path

# Add scripts to path
sys.path.append(str(Path(__file__).parent.parent / "scripts"))
from predict import predict_flow

class PacketApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Camera Detection - GUI")
        self.root.geometry("600x400")
        
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
            btn_frame, text="Classify Device",
            command=self.run_analysis,
            width=18
        )
        self.analyze_button.grid(row=0, column=1, padx=8, pady=4)
        
        self.info_text = tk.Text(root, height=15, width=70, font=("Courier", 9))
        self.info_text.pack(pady=8)
        self.info_text.insert("1.0", "Load a .pcap file to classify.\n")
        self.info_text.configure(state="disabled")
        
        self.loaded_file = None
    
    def load_pcap(self):
        file_path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*"))
        )
        
        if file_path:
            self.file_label.config(text=f"Loaded: {Path(file_path).name}", fg="black")
            self.loaded_file = file_path
            self._show_info(f"File: {Path(file_path).name}\n\nClick 'Classify Device' to analyze.")
    
    def run_analysis(self):
        if not self.loaded_file:
            messagebox.showwarning("No File", "Please load a PCAP file first.")
            return
        
        self._show_info("Analyzing...\nExtracting features...")
        self.root.update()
        
        try:
            predictions, error = predict_flow(self.loaded_file)
            
            if error:
                messagebox.showerror("Error", error)
                self._show_info(f"Error: {error}")
                return
            
            # Format results
            result_text = "="*60 + "\n"
            result_text += "CLASSIFICATION RESULTS\n"
            result_text += "="*60 + "\n\n"
            result_text += f"File: {Path(self.loaded_file).name}\n\n"
            
            result_text += "Model Predictions:\n"
            result_text += "-"*60 + "\n"
            
            for model, result in predictions.items():
                result_text += f"\n{model}:\n"
                result_text += f"  Prediction: {result['prediction'].upper()}\n"
                result_text += f"  Confidence: {result['confidence']:.1%}\n"
            
            # Consensus
            camera_votes = sum(1 for r in predictions.values() if r['prediction'] == 'camera')
            total = len(predictions)
            
            result_text += "\n" + "="*60 + "\n"
            result_text += "CONSENSUS\n"
            result_text += "="*60 + "\n"
            
            if camera_votes == total:
                consensus = "CAMERA"
                result_text += f"\n✓ All models agree: {consensus}\n"
            elif camera_votes == 0:
                consensus = "NON-CAMERA"
                result_text += f"\n✓ All models agree: {consensus}\n"
            else:
                consensus = "CAMERA" if camera_votes > total/2 else "NON-CAMERA"
                result_text += f"\n⚠ Split: {camera_votes}/{total} predict CAMERA\n"
                result_text += f"  Majority: {consensus}\n"
            
            avg_conf = sum(r['confidence'] for r in predictions.values()) / len(predictions)
            result_text += f"\nAverage confidence: {avg_conf:.1%}\n"
            
            self._show_info(result_text)
            messagebox.showinfo("Result", f"Device Type: {consensus}\nConfidence: {avg_conf:.1%}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed:\n{str(e)}")
            self._show_info(f"ERROR: {str(e)}")
    
    def _show_info(self, text):
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", text)
        self.info_text.configure(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketApp(root)
    root.mainloop()