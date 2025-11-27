import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from datetime import datetime
import queue
import json
import os

class AdminServer:
    """Server for admin console communication and monitoring"""
    def __init__(self, app, host="0.0.0.0", port=9999):
        self.app = app
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {addr: socket}
        self.gui_queue = queue.Queue()
        self.running = False
        self.admin_users = {"admin": "password123"}  # Basic auth (use secure method in production)
        self.authenticated_clients = set()

    def start_server(self):
        """Start the admin server"""
        if self.running:
            self.app.log_event("Server is already running.")
            return
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.app.log_event(f"Admin server started on {self.host}:{self.port}")
            threading.Thread(target=self._accept_clients, daemon=True).start()
        except Exception as e:
            self.app.log_event(f"Error starting server: {e}")

    def stop_server(self):
        """Stop the admin server"""
        self.running = False
        try:
            for c in list(self.clients.values()):
                c.close()
            self.clients.clear()
            self.authenticated_clients.clear()
            if self.server_socket:
                self.server_socket.close()
            self.app.log_event("Admin server stopped.")
        except Exception as e:
            self.app.log_event(f"Error stopping server: {e}")

    def _accept_clients(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                self.clients[client_addr] = client_sock
                self.app.log_event(f"Client connected: {client_addr}")
                threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, sock, addr):
        """Handle individual client connections"""
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                message = data.decode("utf-8", errors="ignore")
                
                # Process incoming messages
                for line in message.splitlines():
                    if line.strip():
                        entry = f"[{addr[0]}] {line}"
                        self.gui_queue.put(entry)
                        self._log_to_file("admin_received_logs.txt", entry)
                        
                        # Handle commands if authenticated
                        if addr in self.authenticated_clients:
                            self._process_command(addr, line, sock)
                        elif "AUTH:" in line:
                            self._handle_auth(addr, line, sock)
            
            self.app.log_event(f"Client disconnected: {addr}")
        except Exception as e:
            self.app.log_event(f"Client {addr} error: {e}")
        finally:
            sock.close()
            if addr in self.clients:
                del self.clients[addr]
            if addr in self.authenticated_clients:
                self.authenticated_clients.remove(addr)

    def _handle_auth(self, addr, auth_msg, sock):
        """Handle client authentication"""
        try:
            parts = auth_msg.split(":")
            if len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if username in self.admin_users and self.admin_users[username] == password:
                    self.authenticated_clients.add(addr)
                    sock.send(b"AUTH_SUCCESS")
                    self.app.log_event(f"Client {addr} authenticated as {username}")
                else:
                    sock.send(b"AUTH_FAILED")
                    self.app.log_event(f"Authentication failed for {addr}")
        except Exception as e:
            self.app.log_event(f"Auth error: {e}")

    def _process_command(self, addr, command, sock):
        """Process admin commands from authenticated clients"""
        try:
            if command.startswith("GET_STATS"):
                stats = self._get_system_stats()
                sock.send(json.dumps(stats).encode("utf-8"))
            elif command.startswith("GET_CLIENTS"):
                clients_list = [str(c) for c in self.clients.keys()]
                sock.send(json.dumps({"clients": clients_list}).encode("utf-8"))
            elif command.startswith("KICK:"):
                target = command.split(":", 1)[1]
                self._kick_client(target)
                sock.send(b"KICK_SUCCESS")
        except Exception as e:
            self.app.log_event(f"Command error: {e}")

    def _get_system_stats(self):
        """Get system statistics"""
        return {
            "timestamp": datetime.now().isoformat(),
            "connected_clients": len(self.clients),
            "authenticated_clients": len(self.authenticated_clients),
            "server_running": self.running
        }

    def _kick_client(self, target):
        """Disconnect a specific client"""
        for addr, sock in list(self.clients.items()):
            if str(addr[0]) == target:
                sock.close()
                del self.clients[addr]
                if addr in self.authenticated_clients:
                    self.authenticated_clients.remove(addr)
                self.app.log_event(f"Kicked client: {addr}")
                break

    def broadcast_message(self, message):
        """Broadcast message to all connected clients"""
        try:
            msg_bytes = message.encode("utf-8")
            for sock in list(self.clients.values()):
                try:
                    sock.send(msg_bytes)
                except:
                    pass
        except Exception as e:
            self.app.log_event(f"Broadcast error: {e}")

    def drain_gui_queue(self):
        """Drain the GUI queue and update the log area"""
        try:
            while True:
                entry = self.gui_queue.get_nowait()
                self.app.log_area.insert(tk.END, entry + "\n")
                self.app.log_area.see(tk.END)
        except queue.Empty:
            pass
        self.app.root.after(100, self.drain_gui_queue)

    @staticmethod
    def _log_to_file(filename, message):
        """Helper method to log to file"""
        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(message + "\n")
        except Exception:
            pass


class AdminApp:
    """Main admin application GUI"""
    def __init__(self, root):
        self.root = root
        self.root.title("USB Admin Monitoring & Control Console - Forensics & Monitoring Toolkit")
        self.root.geometry("1100x700")
        self.root.resizable(True, True)

        self.server = AdminServer(self)
        self.create_widgets()
        self.root.after(100, self.server.drain_gui_queue)

    def create_widgets(self):
        """Create GUI widgets"""
        # Title
        title = tk.Label(self.root, text="USB Monitoring Toolkit - Admin Console", 
                        font=("Arial", 18, "bold"), fg="#2c3e50")
        title.pack(pady=10)

        # Status bar
        self.status_frame = tk.Frame(self.root, bg="#ecf0f1", relief=tk.SUNKEN, height=30)
        self.status_frame.pack(fill=tk.X, padx=5, pady=2)
        self.status_label = tk.Label(self.status_frame, text="Status: Stopped", 
                                     bg="#ecf0f1", fg="#e74c3c", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tab 1: Logs
        self.logs_frame = tk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Live Logs")
        
        self.log_area = scrolledtext.ScrolledText(self.logs_frame, width=130, height=25, 
                                                   wrap=tk.WORD, state=tk.NORMAL, font=("Courier", 9))
        self.log_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Tab 2: Controls
        self.control_frame = tk.Frame(self.notebook)
        self.notebook.add(self.control_frame, text="Server Controls")
        self._create_control_tab()

        # Tab 3: Client Management
        self.client_frame = tk.Frame(self.notebook)
        self.notebook.add(self.client_frame, text="Client Management")
        self._create_client_tab()

        # Tab 4: Settings
        self.settings_frame = tk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        self._create_settings_tab()

        # Bottom button frame
        btn_frame = tk.Frame(self.root, bg="#ecf0f1")
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        # Center container for start/stop buttons
        center_btn_frame = tk.Frame(btn_frame, bg="#ecf0f1")
        center_btn_frame.pack(side=tk.LEFT, expand=True)

        self.start_btn = tk.Button(center_btn_frame, text="▶ Start Monitor", command=self.start_server,
                                   bg="#27ae60", fg="white", font=("Arial", 11, "bold"),
                                   padx=15, pady=8, relief=tk.RAISED)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(center_btn_frame, text="⏹ Stop Monitor", command=self.stop_server,
                                  bg="#e74c3c", fg="white", font=("Arial", 11, "bold"),
                                  padx=15, pady=8, relief=tk.RAISED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        clear_btn = tk.Button(btn_frame, text="🗑 Clear Logs", command=self.clear_logs,
                             bg="#3498db", fg="white", font=("Arial", 11, "bold"),
                             padx=15, pady=8, relief=tk.RAISED)
        clear_btn.pack(side=tk.RIGHT, padx=5)

    def _create_control_tab(self):
        """Create server control tab"""
        frame = tk.Frame(self.control_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(frame, text="Server Controls", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        control_info = tk.Frame(frame, relief=tk.SUNKEN, borderwidth=1)
        control_info.pack(fill=tk.BOTH, expand=True, pady=10)

        info_text = scrolledtext.ScrolledText(control_info, height=15, width=80, wrap=tk.WORD)
        info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        info_content = """
SERVER CONTROL PANEL
====================

Start Server: Begins listening for admin client connections on port 9999
Stop Server: Closes all connections and stops the server

Connected Clients: Displays the number of currently connected clients
Authenticated Clients: Shows how many clients have successfully authenticated

ADMIN COMMANDS:
- GET_STATS: Retrieve server statistics
- GET_CLIENTS: List all connected clients
- KICK:<IP>: Disconnect a specific client
- BROADCAST:<MESSAGE>: Send message to all clients

AUTHENTICATION:
- Format: AUTH:<username>:<password>
- Default credentials: admin / password123
- Change credentials in Settings tab

CLIENT MANAGEMENT:
- View all connected clients
- Monitor client activity
- Disconnect individual clients
- View client IP and connection time
        """
        info_text.insert("1.0", info_content)
        info_text.config(state=tk.DISABLED)

    def _create_client_tab(self):
        """Create client management tab"""
        frame = tk.Frame(self.client_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(frame, text="Connected Clients", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        # Client list
        self.client_listbox = tk.Listbox(frame, height=15, width=80, font=("Courier", 10))
        scrollbar = tk.Scrollbar(frame, command=self.client_listbox.yview)
        self.client_listbox.config(yscrollcommand=scrollbar.set)
        self.client_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Control buttons
        btn_frame = tk.Frame(self.client_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Button(btn_frame, text="🔄 Refresh", command=self.refresh_client_list,
                 bg="#3498db", fg="white", padx=10).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_frame, text="🔴 Kick Client", command=self.kick_selected_client,
                 bg="#e74c3c", fg="white", padx=10).pack(side=tk.LEFT, padx=5)

        # Info label
        self.client_info_label = tk.Label(self.client_frame, text="Total Clients: 0", font=("Arial", 10))
        self.client_info_label.pack(pady=5)

    def _create_settings_tab(self):
        """Create settings tab"""
        frame = tk.Frame(self.settings_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(frame, text="Server Settings", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        # Host setting
        tk.Label(frame, text="Server Host:", font=("Arial", 10)).pack(anchor=tk.W, pady=2)
        self.host_entry = tk.Entry(frame, width=40, font=("Arial", 10))
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.pack(anchor=tk.W, pady=5)

        # Port setting
        tk.Label(frame, text="Server Port:", font=("Arial", 10)).pack(anchor=tk.W, pady=2)
        self.port_entry = tk.Entry(frame, width=40, font=("Arial", 10))
        self.port_entry.insert(0, "9999")
        self.port_entry.pack(anchor=tk.W, pady=5)

        # Save button
        tk.Button(frame, text="💾 Save Settings", command=self.save_settings,
                 bg="#27ae60", fg="white", padx=10).pack(anchor=tk.W, pady=10)

        tk.Label(frame, text="\nAdmin Credentials", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        tk.Label(frame, text="Username:", font=("Arial", 10)).pack(anchor=tk.W, pady=2)
        self.admin_user_entry = tk.Entry(frame, width=40, font=("Arial", 10))
        self.admin_user_entry.insert(0, "admin")
        self.admin_user_entry.pack(anchor=tk.W, pady=5)

        tk.Label(frame, text="Password:", font=("Arial", 10)).pack(anchor=tk.W, pady=2)
        self.admin_pass_entry = tk.Entry(frame, width=40, font=("Arial", 10), show="*")
        self.admin_pass_entry.insert(0, "password123")
        self.admin_pass_entry.pack(anchor=tk.W, pady=5)

        tk.Button(frame, text="🔐 Update Credentials", command=self.update_credentials,
                 bg="#e67e22", fg="white", padx=10).pack(anchor=tk.W, pady=10)

    def start_server(self):
        """Start the admin server"""
        self.server.start_server()
        self.status_label.config(text="Status: Running", fg="#27ae60")

    def stop_server(self):
        """Stop the admin server"""
        self.server.stop_server()
        self.status_label.config(text="Status: Stopped", fg="#e74c3c")

    def clear_logs(self):
        """Clear log display"""
        self.log_area.delete("1.0", tk.END)
        self.log_event("Logs cleared.")

    def refresh_client_list(self):
        """Refresh the client list display"""
        self.client_listbox.delete(0, tk.END)
        for addr in self.server.clients.keys():
            auth_status = "✓ Auth" if addr in self.server.authenticated_clients else "✗ Not Auth"
            self.client_listbox.insert(tk.END, f"{addr[0]}:{addr[1]} [{auth_status}]")
        self.client_info_label.config(text=f"Total Clients: {len(self.server.clients)}")

    def kick_selected_client(self):
        """Kick the selected client"""
        selection = self.client_listbox.curselection()
        if selection:
            item = self.client_listbox.get(selection[0])
            ip = item.split(":")[0]
            self.server._kick_client(ip)
            self.refresh_client_list()

    def save_settings(self):
        """Save server settings"""
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            self.server.host = host
            self.server.port = port
            messagebox.showinfo("Success", "Settings saved successfully!")
            self.log_event(f"Settings updated: {host}:{port}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def update_credentials(self):
        """Update admin credentials"""
        try:
            username = self.admin_user_entry.get()
            password = self.admin_pass_entry.get()
            if username and password:
                self.server.admin_users = {username: password}
                messagebox.showinfo("Success", "Credentials updated successfully!")
                self.log_event(f"Admin credentials updated for user: {username}")
            else:
                messagebox.showerror("Error", "Username and password cannot be empty!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update credentials: {e}")

    def log_event(self, message):
        """Log an event with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_area.insert(tk.END, entry + "\n")
        self.log_area.see(tk.END)
        try:
            with open("admin_console_log.txt", "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except Exception:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = AdminApp(root)
    root.mainloop()
