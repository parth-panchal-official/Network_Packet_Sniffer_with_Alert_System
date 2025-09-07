import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
import csv
import threading
import time
import os
from collections import Counter
from ttkbootstrap import Style as ttkbStyle, Frame as ttkbFrame, Button as ttkbButton
from ttkbootstrap.constants import *
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from sniffer import set_credential_sniffing, start_sniffing

BLOCKED_IPS = set()

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1100x650")

        self.sniffing_enabled = True

        style = ttkbStyle("darkly")

        self.sidebar = ttkbFrame(self.root, padding=10)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)

        self.main_area = ttkbFrame(self.root)
        self.main_area.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

        self.nav_buttons = []
        for text, command in [
            ("Summary", self.show_summary),
            ("Logs", self.show_logs),
            ("Settings", self.show_settings)
        ]:
            btn = ttkbButton(self.sidebar, text=text, bootstyle=SECONDARY, command=command)
            btn.pack(fill=tk.X, pady=5)
            self.nav_buttons.append(btn)

        self.pages = {}
        for name in ("summary", "logs", "settings"):
            frame = ttkbFrame(self.main_area)
            self.pages[name] = frame

        self.build_summary_tab(self.pages["summary"])
        self.build_logs_tab(self.pages["logs"])
        self.build_settings_tab(self.pages["settings"])

        self.pages["summary"].pack(expand=True, fill=tk.BOTH)
        self.current_page = "summary"

        self.ui_thread = threading.Thread(target=self.refresh_ui, daemon=True)
        self.ui_thread.start()

        self.sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniffing_thread.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.root.bind("<Control-1>", lambda e: self.show_summary())
        self.root.bind("<Control-2>", lambda e: self.show_logs())
        self.root.bind("<Control-3>", lambda e: self.show_settings())

    def build_summary_tab(self, frame):
        ttk.Label(frame, text="Live Packet Summary", font=("Arial", 16)).pack(pady=10)

        stats_frame = ttk.Frame(frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)

        self.total_packets_label = ttk.Label(stats_frame, text="Total Packets: 0")
        self.total_packets_label.pack(side=tk.LEFT, padx=10)

        self.tcp_packets_label = ttk.Label(stats_frame, text="TCP: 0")
        self.tcp_packets_label.pack(side=tk.LEFT, padx=10)

        self.udp_packets_label = ttk.Label(stats_frame, text="UDP: 0")
        self.udp_packets_label.pack(side=tk.LEFT, padx=10)

        self.anomaly_count_label = ttk.Label(stats_frame, text="Anomalies: 0")
        self.anomaly_count_label.pack(side=tk.LEFT, padx=10)

        toggle_frame = ttk.Frame(frame)
        toggle_frame.pack(pady=5)

        ttk.Label(toggle_frame, text="Graph Mode:").pack(side=tk.LEFT)
        self.graph_mode = tk.StringVar(value="Protocol")
        ttk.Radiobutton(toggle_frame, text="Protocol", variable=self.graph_mode, value="Protocol", command=self.update_graph).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(toggle_frame, text="Port", variable=self.graph_mode, value="Port", command=self.update_graph).pack(side=tk.LEFT, padx=5)

        self.figure = Figure(figsize=(6, 3), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def build_logs_tab(self, frame):
        self.log_tabs = ttk.Notebook(frame)

        self.raw_log_tab = ttk.Frame(self.log_tabs)
        self.dns_tab = ttk.Frame(self.log_tabs)
        self.cred_tab = ttk.Frame(self.log_tabs)

        self.log_tabs.add(self.raw_log_tab, text="Raw Logs")
        self.log_tabs.add(self.dns_tab, text="DNS Requests")
        self.log_tabs.add(self.cred_tab, text="Credentials")
        self.log_tabs.pack(expand=True, fill=tk.BOTH)

        for tab in [self.raw_log_tab, self.dns_tab, self.cred_tab]:
            search_frame = ttk.Frame(tab)
            search_frame.pack(fill=tk.X, pady=5)
            tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
            entry = ttk.Entry(search_frame)
            entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            button = ttk.Button(search_frame, text="Filter", command=lambda e=entry, t=tab: self.apply_filter(e, t))
            button.pack(side=tk.LEFT)
            export_button = ttk.Button(search_frame, text="Export", command=lambda t=tab: self.export_tab_logs(t))
            export_button.pack(side=tk.RIGHT)

        self.raw_text = tk.Text(self.raw_log_tab)
        self.raw_text.pack(expand=True, fill=tk.BOTH)

        self.dns_tree = ttk.Treeview(self.dns_tab, columns=("Timestamp", "IP", "Query"), show="headings")
        for col in ("Timestamp", "IP", "Query"):
            self.dns_tree.heading(col, text=col)
        self.dns_tree.pack(fill=tk.BOTH, expand=True)

        self.cred_tree = ttk.Treeview(self.cred_tab, columns=("Timestamp", "IP", "Data"), show="headings")
        for col in ("Timestamp", "IP", "Data"):
            self.cred_tree.heading(col, text=col)
        self.cred_tree.pack(fill=tk.BOTH, expand=True)

    def build_settings_tab(self, frame):
        ttk.Label(frame, text="Settings", font=("Arial", 16)).pack(pady=10)

        toggle_frame = ttk.Frame(frame)
        toggle_frame.pack(pady=5)

        self.credential_sniffing = tk.BooleanVar(value=True)
        toggle_btn = ttk.Checkbutton(toggle_frame, text="Enable Credential Sniffing", variable=self.credential_sniffing, command=self.toggle_credential_sniffing)
        toggle_btn.pack()

    def toggle_credential_sniffing(self):
        set_credential_sniffing(self.credential_sniffing.get())

    def show_summary(self):
        self._switch_tab("summary")

    def show_logs(self):
        self._switch_tab("logs")

    def show_settings(self):
        self._switch_tab("settings")

    def _switch_tab(self, name):
        self.pages[self.current_page].pack_forget()
        self.pages[name].pack(expand=True, fill=tk.BOTH)
        self.current_page = name

    def refresh_ui(self):
        while True:
            self.update_raw_logs()
            self.update_dns_tree()
            self.update_credential_tree()
            self.update_summary_dashboard()
            self.update_graph()
            time.sleep(5)

    def update_summary_dashboard(self):
        conn = sqlite3.connect("packet_logs.db")
        cur = conn.cursor()
        cur.execute("SELECT protocol FROM packets")
        protocols = [row[0] for row in cur.fetchall()]
        conn.close()

        total = len(protocols)
        tcp = protocols.count("TCP")
        udp = protocols.count("UDP")
        anomalies = len(BLOCKED_IPS)

        self.total_packets_label.config(text=f"Total Packets: {total}")
        self.tcp_packets_label.config(text=f"TCP: {tcp}")
        self.udp_packets_label.config(text=f"UDP: {udp}")
        self.anomaly_count_label.config(text=f"Anomalies: {anomalies}")

    def update_graph(self):
        conn = sqlite3.connect("packet_logs.db")
        cur = conn.cursor()
        if self.graph_mode.get() == "Protocol":
            cur.execute("SELECT protocol FROM packets")
            values = [row[0] for row in cur.fetchall()]
            counts = Counter(values)
        else:
            cur.execute("SELECT dst_port FROM packets WHERE dst_port IS NOT NULL")
            values = [str(row[0]) for row in cur.fetchall()]
            counts = Counter(values)
            if len(counts) > 20:
                counts = dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:20])
        conn.close()
        self.ax.clear()
        self.ax.bar(counts.keys(), counts.values(), color="skyblue")
        self.ax.set_title(f"{self.graph_mode.get()} Usage")
        self.ax.set_ylabel("Count")
        self.ax.tick_params(axis='x', labelrotation=45)
        self.canvas.draw()

    def update_raw_logs(self):
        conn = sqlite3.connect("packet_logs.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 20")
        rows = cur.fetchall()
        conn.close()
        self.raw_text.delete("1.0", tk.END)
        for row in rows:
            self.raw_text.insert(tk.END, f"{row}\n")

    def update_dns_tree(self):
        for i in self.dns_tree.get_children():
            self.dns_tree.delete(i)
        conn = sqlite3.connect("dns_logs.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM dns_requests ORDER BY timestamp DESC LIMIT 20")
        rows = cur.fetchall()
        conn.close()
        for row in rows:
            self.dns_tree.insert('', 'end', values=row)

    def update_credential_tree(self):
        for i in self.cred_tree.get_children():
            self.cred_tree.delete(i)
        conn = sqlite3.connect("credentials.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM credentials ORDER BY timestamp DESC LIMIT 20")
        rows = cur.fetchall()
        conn.close()
        for row in rows:
            self.cred_tree.insert('', 'end', values=row)

    def apply_filter(self, entry_widget, tab):
        keyword = entry_widget.get().lower()
        if tab == self.raw_log_tab:
            self.raw_text.delete("1.0", tk.END)
            conn = sqlite3.connect("packet_logs.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM packets")
            rows = cur.fetchall()
            conn.close()
            for row in rows:
                if keyword in str(row).lower():
                    self.raw_text.insert(tk.END, f"{row}\n")
        elif tab == self.dns_tab:
            self.update_dns_tree()
            children = self.dns_tree.get_children()
            for item in children:
                if keyword not in str(self.dns_tree.item(item)['values']).lower():
                    self.dns_tree.delete(item)
        elif tab == self.cred_tab:
            self.update_credential_tree()
            children = self.cred_tree.get_children()
            for item in children:
                if keyword not in str(self.cred_tree.item(item)['values']).lower():
                    self.cred_tree.delete(item)

    def export_tab_logs(self, tab):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        if tab == self.raw_log_tab:
            conn = sqlite3.connect("packet_logs.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM packets")
        elif tab == self.dns_tab:
            conn = sqlite3.connect("dns_logs.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM dns_requests")
        elif tab == self.cred_tab:
            conn = sqlite3.connect("credentials.db")
            cur = conn.cursor()
            cur.execute("SELECT * FROM credentials")
        rows = cur.fetchall()
        conn.close()

        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        messagebox.showinfo("Export", "Logs exported to: " + path)

    def on_close(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
