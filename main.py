import threading
import tkinter as tk
from gui import PacketSnifferGUI
from sniffer import start_sniffing

# Start packet sniffer in a background thread
threading.Thread(target=start_sniffing, daemon=True).start()

# Launch GUI
if __name__ == '__main__':
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
