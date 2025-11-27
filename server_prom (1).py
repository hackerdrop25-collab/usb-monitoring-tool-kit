import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
import queue

class AdminServer:
    def __init__(self, app, host="0.0.0.0", port=9999):
        self.app = app
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {addr: socket}
        self.gui_queue = queue.Queue()
        self.running = False

    def start_server(self):
        if self.running:
            self.app.log_event("Server is already running.")
            return
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.app.log_event(f"Admin server started on {self.host}:{self.port}")
            threading.Thread(target=self._accept_clients, daemon=True).start()
        except Exception as e:
            self.app.log_event(f"Error starting server: {e}")

    def stop_server(self):
        self.running = False
        try:
            for c in list(self.clients.values()):
                c.close()
            self.clients.clear()
            if self.server_socket:
                self.server_socket.close()
            self.app.log_event("Admin server stopped.")
        except Exception as e:
            self.app.log_event(f"Error stopping server: {e}")

    def _accept_clients(self):
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                self.clients[client_addr] = client_sock
                self.app.log_event(f"Client connected: {client_addr}")
                threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, sock, addr):
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                message = data.decode("utf-8", errors="ignore")
                for line in message.splitlines():
                    entry = f"[{addr[0]}] {line}"
                    self.gui_queue.put(entry)
                    with open("admin_received_logs.txt", "a", encoding="utf-8") as f:
                        f.write(entry + "\n")
            self.app.log_event(f"Client disconnected: {addr}")
        except Exception as e:
            self.app.log_event(f"Client {addr} error: {e}")
        finally:
            sock.close()
            if addr in self.clients:
                del self.clients[addr]

    def drain_gui_queue(self):
        try:
            while True:
                entry = self.gui_queue.get_nowait()
                self.app.log_area.insert(tk.END, entry + "\n")
                self.app.log_area.see(tk.END)
        except queue.Empty:
            pass
        self.app.root.after(100, self.drain_gui_queue)


class AdminApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Admin Console - Forensics & Monitoring Toolkit")
        self.root.geometry("950x550")

        self.server = AdminServer(self)
        self.create_widgets()
        self.root.after(100, self.server.drain_gui_queue)

    def create_widgets(self):
        title = tk.Label(self.root, text="USB Admin Monitoring Console", font=("Arial", 16, "bold"))
        title.pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(self.root, width=115, height=25, wrap=tk.WORD, state=tk.NORMAL)
        self.log_area.pack(padx=10, pady=10)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        self.start_btn = tk.Button(btn_frame, text="Start Server", command=self.server.start_server)
        self.start_btn.grid(row=0, column=0, padx=10)

        self.stop_btn = tk.Button(btn_frame, text="Stop Server", command=self.server.stop_server)
        self.stop_btn.grid(row=0, column=1, padx=10)

    def log_event(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_area.insert(tk.END, entry + "\n")
        self.log_area.see(tk.END)
        with open("admin_server_log.txt", "a", encoding="utf-8") as f:
            f.write(entry + "\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = AdminApp(root)
    root.mainloop()