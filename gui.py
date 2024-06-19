import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from scapy.all import sniff, TCP, UDP, IP
from sniffer import Sniffer  # Ensure this import works
import time

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        self.create_widgets()

        self.sniffer = Sniffer()
        self.sniffing = False
        self.packet_count = 0

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        control_frame = ttk.Frame(main_frame, padding="10 10 10 10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)

        self.save_log_button = ttk.Button(control_frame, text="Save Log", command=self.save_log)
        self.save_log_button.grid(row=0, column=2, padx=5)

        status_frame = ttk.Frame(main_frame, padding="10 10 10 10")
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))

        self.packet_count_label = ttk.Label(status_frame, text="Packets Processed: 0")
        self.packet_count_label.grid(row=0, column=0, sticky=tk.W)

        self.last_packet_label = ttk.Label(status_frame, text="Last Packet: None")
        self.last_packet_label.grid(row=0, column=1, sticky=tk.W)

        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10 10 10 10")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.log = scrolledtext.ScrolledText(log_frame, width=100, height=30)
        self.log.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        main_frame.rowconfigure(2, weight=1)
        main_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

    def start_sniffing(self):
        self.sniffing = True
        self.packet_count = 0
        self.update_status()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.run_sniffer).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def run_sniffer(self):
        try:
            sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing)
        except PermissionError:
            messagebox.showerror("Permission Error", "Operation not permitted. Please run the script with elevated privileges.")
            self.stop_sniffing()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while sniffing: {str(e)}")
            self.stop_sniffing()

    def process_packet(self, packet):
        try:
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                prediction = self.sniffer.predict_packet_class(packet)
                if prediction is not None:
                    self.log.insert(tk.END, f"Predicted Class: {prediction}\n")
                    self.log.see(tk.END)
                    self.packet_count += 1
                    self.update_status(packet)
            else:
                raise AttributeError("Packet does not have TCP or UDP layer")
        except AttributeError as ae:
            self.log.insert(tk.END, f"Error processing packet: {ae}\n")
            self.log.see(tk.END)
        except Exception as e:
            self.log.insert(tk.END, f"Error processing packet: {e}\n")
            self.log.see(tk.END)

    def update_status(self, packet=None):
        self.packet_count_label.config(text=f"Packets Processed: {self.packet_count}")
        if packet:
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                self.last_packet_label.config(text=f"Last Packet: {ip_layer.src} -> {ip_layer.dst}")
            else:
                self.last_packet_label.config(text="Last Packet: Unknown")

    def save_log(self):
        log_content = self.log.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as log_file:
                log_file.write(log_content)
            messagebox.showinfo("Save Log", "Log saved successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()

