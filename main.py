import customtkinter as ctk
import tkinter.messagebox as tkmb
import os
import json
import threading
import time
import requests
import subprocess
import concurrent.futures
# import pyperclip 
from utils import parse_vmess, parse_vless, parse_trojan, generate_xray_config, set_system_proxy
from xray_runner import XrayRunner

# --- Configuration ---
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class ConfigCard(ctk.CTkFrame):
    """A card-like frame representing a single configuration."""
    def __init__(self, master, config_item, connect_cb, delete_cb, index, is_connected=False):
        # Premium dark gray color, highlight if connected
        fg_color = "#2a2d2e" if not is_connected else ("#3B8ED0", "#1F6AA5")
        super().__init__(master, fg_color=fg_color, corner_radius=8)
        
        self.config_item = config_item
        self.index = index
        self.connect_cb = connect_cb
        self.delete_cb = delete_cb
        
        # Make the card itself clickable
        self.bind("<Button-1>", lambda e: self.connect_cb(self.index))
        # Cursor change on hover
        self.configure(cursor="hand2")

        # 1. Alias Label
        self.name_label = ctk.CTkLabel(
            self, text=config_item['alias'], 
            font=("Roboto", 14, "bold"), anchor="w",
            text_color="white" if is_connected else ["#333", "#ddd"]
        )
        self.name_label.pack(side="left", padx=(15, 5), pady=10)
        self.name_label.bind("<Button-1>", lambda e: self.connect_cb(self.index))

        # 2. Ping Label (Aligned next to name)
        last_ping = config_item.get('last_ping')
        
        # We explicitly check for a special "Pinging..." state marker
        if config_item.get('is_pinging_active'):
             p_text = "- ⏳ Pinging..."
             p_color = "#00b4d8"
        elif last_ping is not None:
            if last_ping == "Fail":
                p_text = "- Fail"
                p_color = "#ff4444"
            else:
                p_text = f"- {last_ping} ms"
                try:
                    p_val = int(last_ping)
                    if p_val < 1500: p_color = "#00ff00"
                    elif p_val < 3000: p_color = "#ffaa00"
                    else: p_color = "#ff4444"
                except:
                    p_color = "gray"
        else:
            p_text = "- ??? ms"  # Placeholder to keep layout clean until pinged
            p_color = "gray"
            
        self.ping_lbl = ctk.CTkLabel(self, text=p_text, font=("Roboto", 12, "bold"), text_color=p_color, width=100, anchor="w")
        self.ping_lbl.pack(side="left", padx=5)
        self.ping_lbl.bind("<Button-1>", lambda e: self.connect_cb(self.index))

        # 3. Delete Button (Far right)
        self.btn_del = ctk.CTkButton(
            self, text="×", width=30, height=30, 
            fg_color="transparent", hover_color="#ff4444", text_color="gray",
            font=("Arial", 16, "bold"),
            command=lambda: self.delete_cb(self.index)
        )
        self.btn_del.pack(side="right", padx=10)

        # 4. Badges (Right side, before Delete)
        
        # TLS badge (if applicable)
        stream_settings = config_item['outbound'].get('streamSettings', {})
        security = stream_settings.get('security', 'none').upper()
        
        if security == "TLS":
            self.tls_frame = ctk.CTkFrame(self, fg_color="#333", border_width=1, border_color="gray", corner_radius=4)
            self.tls_frame.pack(side="right", padx=5, pady=10)
            self.tls_badge = ctk.CTkLabel(self.tls_frame, text="TLS", font=("Roboto", 10), text_color="white", width=40, height=20)
            self.tls_badge.pack(padx=2, pady=2)
            self.tls_frame.bind("<Button-1>", lambda e: self.connect_cb(self.index))
            self.tls_badge.bind("<Button-1>", lambda e: self.connect_cb(self.index))

        # Transport badge
        network = stream_settings.get('network', 'tcp').upper()
        self.trans_frame = ctk.CTkFrame(self, fg_color="#333", border_width=1, border_color="gray", corner_radius=4)
        self.trans_frame.pack(side="right", padx=5, pady=10)
        self.trans_badge = ctk.CTkLabel(self.trans_frame, text=network, font=("Roboto", 10), text_color="white", width=40, height=20)
        self.trans_badge.pack(padx=2, pady=2)
        self.trans_frame.bind("<Button-1>", lambda e: self.connect_cb(self.index))
        self.trans_badge.bind("<Button-1>", lambda e: self.connect_cb(self.index))

        # Protocol badge
        protocol = config_item['outbound'].get('protocol', 'unknown').upper()
        self.proto_frame = ctk.CTkFrame(self, fg_color="#333", border_width=1, border_color="gray", corner_radius=4)
        self.proto_frame.pack(side="right", padx=(5, 10), pady=10)
        self.proto_badge = ctk.CTkLabel(self.proto_frame, text=protocol, font=("Roboto", 10), text_color="white", width=40, height=20)
        self.proto_badge.pack(padx=2, pady=2)
        self.proto_frame.bind("<Button-1>", lambda e: self.connect_cb(self.index))
        self.proto_badge.bind("<Button-1>", lambda e: self.connect_cb(self.index))



class BabyVPNApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Config
        self.title("Baby VPN")
        self.geometry("900x550")
        self.minsize(800, 450)
        
        # Grid Layout (1 row, 2 columns: Sidebar & Main)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0) # Sidebar fixed width
        self.grid_columnconfigure(1, weight=1) # Main area expands
        
        # Data
        self.configs = [] # List of dicts
        self.selected_index = -1
        
        # Xray Handlers
        self.xray_main = XrayRunner(config_filename="config.json", log_filename="xray_log.txt")
        self.xray_ping = XrayRunner(config_filename="ping_config.json", log_filename="xray_ping_log.txt")
        
        self.is_connected = False
        self.is_pinging = False

        # Build UI
        self.create_sidebar()
        self.create_main_area()

        # Load existing configs
        self.load_configs()

        # Key Bindings
        self.bind("<Control-v>", self.paste_config)
        
        # Handle Exit
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_sidebar(self):
        """Creates the left sidebar with controls and status."""
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#1e1e24")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1) # Spacer

        # Logo / Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, text="Baby VPN", 
            font=ctk.CTkFont(size=24, weight="bold"), text_color="#00b4d8"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Paste Button (Alternative to Ctrl+V)
        self.btn_paste = ctk.CTkButton(
            self.sidebar_frame, text="Paste Config", 
            height=30, fg_color="#333", hover_color="#555",
            command=self.paste_config
        )
        self.btn_paste.grid(row=1, column=0, padx=20, pady=(10, 20))

        # Status Indicator
        self.status_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.status_frame.grid(row=2, column=0, padx=20, pady=(20, 10))
        
        self.status_dot = ctk.CTkLabel(self.status_frame, text="●", text_color="gray", font=("Arial", 16))
        self.status_dot.pack(side="left", padx=(0,5))
        self.status_label = ctk.CTkLabel(self.status_frame, text="Disconnected", font=ctk.CTkFont(size=14))
        self.status_label.pack(side="left")

        # Connect Button (Big)
        self.btn_connect = ctk.CTkButton(
            self.sidebar_frame, text="Connect", 
            height=40, font=ctk.CTkFont(weight="bold"),
            command=self.toggle_connection, state="disabled"
        )
        self.btn_connect.grid(row=3, column=0, padx=20, pady=10)

        # Mux Toggle
        self.mux_switch = ctk.CTkSwitch(
            self.sidebar_frame, text="Enable Mux",
            font=ctk.CTkFont(size=12),
            onvalue=True, offvalue=False
        )
        self.mux_switch.grid(row=4, column=0, padx=20, pady=(5, 10))

        # Bottom section: Ping, About
        self.btn_ping = ctk.CTkButton(
            self.sidebar_frame, text="Ping Test", 
            fg_color="#444", hover_color="#555",
            command=self.run_ping_check, state="disabled"
        )
        self.btn_ping.grid(row=6, column=0, padx=20, pady=(10, 5))

        self.btn_ping_all = ctk.CTkButton(
            self.sidebar_frame, text="Ping All", 
            fg_color="#444", hover_color="#555",
            command=self.run_ping_all, state="disabled"
        )
        self.btn_ping_all.grid(row=7, column=0, padx=20, pady=(5, 5))

        self.btn_about = ctk.CTkButton(
            self.sidebar_frame, text="About Baby VPN", 
            fg_color="transparent", hover_color="#333", text_color="#00b4d8",
            border_width=1, border_color="#00b4d8",
            command=self.show_about
        )
        self.btn_about.grid(row=8, column=0, padx=20, pady=(5, 20))

    def show_about(self):
        try:
            xray_ver = subprocess.run([self.xray_main.xray_path, "-version"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            core_info = xray_ver.stdout.split('\n')[0] if xray_ver.stdout else "Unknown"
        except Exception:
            core_info = "Not Found or Error"

        about_text = (
            "Baby VPN v1.2.0 Ultimate\n"
            "A fast, lightweight & modern Xray client.\n\n"
            f"Core: {core_info}\n"
            "Protocols: VMESS, VLESS, Trojan\n"
            "Transports: TCP, KCP, WS, HTTP, XHTTP, H2, QUIC, gRPC\n"
            "UI: CustomTkinter\n\n"
            "Developer: Emad"
        )
        tkmb.showinfo("About Baby VPN", about_text)

    def create_main_area(self):
        """Creates the main area housing the server list and console."""
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.main_frame.grid_columnconfigure(0, weight=1) # Expand internally
        self.main_frame.grid_rowconfigure(0, weight=3) # List area
        self.main_frame.grid_rowconfigure(1, weight=1) # Console area
        
        # Scrollable Config List
        self.scroll_frame = ctk.CTkScrollableFrame(self.main_frame, label_text="Server Configurations")
        self.scroll_frame.grid(row=0, column=0, sticky="nsew", pady=(0,10))
        
        self.lbl_empty = ctk.CTkLabel(self.scroll_frame, text="No servers added yet.\nCopy a Vmess/Vless link and press Ctrl+V.", text_color="gray")
        self.lbl_empty.pack(pady=40)

        # Console Logger
        self.log_box = ctk.CTkTextbox(self.main_frame, height=100, font=("Consolas", 11), fg_color="#121212", text_color="#00ff00")
        self.log_box.grid(row=1, column=0, sticky="nsew")
        self.log_box.insert("end", "[System] Baby VPN Initialized.\n")
        self.log_box.configure(state="disabled")

    def log(self, message):
        """Appends message to the on-screen console."""
        self.log_box.configure(state="normal")
        time_str = time.strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{time_str}] {message}\n")
        self.log_box.configure(state="disabled")
        self.log_box.see("end")

    def load_configs(self):
        """Loads configurations from servers.json."""
        if os.path.exists("servers.json"):
            try:
                with open("servers.json", "r", encoding="utf-8") as f:
                    self.configs = json.load(f)
                if self.configs:
                    self.selected_index = 0
                self.refresh_list()
            except Exception as e:
                self.log(f"Failed to load servers.json: {e}")

    def save_configs(self):
        """Saves current configurations to servers.json."""
        try:
            with open("servers.json", "w", encoding="utf-8") as f:
                json.dump(self.configs, f, indent=4)
        except Exception as e:
            self.log(f"Failed to save servers.json: {e}")

    def paste_config(self, event=None):
        try:
            # We explicitly use the root's clipboard method
            content = self.clipboard_get()
            if content:
                content = content.strip()
                # Run the add_config logic slightly delayed so UI doesn't freeze or ignore
                self.after(50, lambda: self.add_config(content))
        except Exception as e:
            self.log("Clipboard empty or not accessible.")

    def add_config(self, link):
        outbound = None
        alias = "Config"
        
        try:
            if link.startswith("vmess://"):
                outbound, alias = parse_vmess(link)
            elif link.startswith("vless://"):
                outbound, alias = parse_vless(link)
            elif link.startswith("trojan://"):
                outbound, alias = parse_trojan(link)
            else:
                self.log("Ignored: Clipboard does not contain a valid vmess/vless/trojan link.")
                return
        except Exception as e:
            self.log(f"Parse error: {e}")
            return
            
        if not outbound:
            self.log("Failed to parse config from link.")
            return

        # Handle duplicate names or missing names
        if not alias: alias = f"Server {len(self.configs) + 1}"
        
        config_item = {'alias': alias, 'link': link, 'outbound': outbound}
        self.configs.append(config_item)
        
        # Auto-select if it's the first one
        if len(self.configs) == 1:
            self.selected_index = 0
            
        self.save_configs()
        self.refresh_list()
        self.log(f"Added Server: {alias}")

    def refresh_list(self):
        """Redraws the configuration list inside the scroll frame."""
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        if not self.configs:
            self.lbl_empty = ctk.CTkLabel(self.scroll_frame, text="No servers added yet.\nCopy a Vmess/Vless link and press Ctrl+V.", text_color="gray")
            self.lbl_empty.pack(pady=40)
            self.btn_connect.configure(state="disabled")
            self.btn_ping.configure(state="disabled")
            return

        for idx, cfg in enumerate(self.configs):
            is_conn = (idx == self.selected_index and self.is_connected)
            card = ConfigCard(self.scroll_frame, cfg, self.select_config, self.delete_config, idx, is_connected=is_conn)
            card.pack(fill="x", pady=4, padx=5)
            
            # Simple highlight for selected but NOT connected
            if idx == self.selected_index and not self.is_connected:
                card.configure(border_width=2, border_color="#00b4d8")

        # Enable buttons based on selection
        if self.selected_index >= 0:
            self.btn_connect.configure(state="normal")
            self.btn_ping.configure(state="normal" if not self.is_pinging else "disabled")
        else:
             self.btn_connect.configure(state="disabled")
             self.btn_ping.configure(state="disabled")

        self.btn_ping_all.configure(state="normal" if (self.configs and not self.is_pinging) else "disabled")

    def delete_config(self, index):
        if self.is_connected and index == self.selected_index:
            tkmb.showerror("Error", "Cannot delete the active connection. Disconnect first.")
            return

        name = self.configs[index]['alias']
        del self.configs[index]
        self.log(f"Deleted Server: {name}")
        
        if index == self.selected_index:
            self.selected_index = -1
        elif index < self.selected_index:
            self.selected_index -= 1
            
        self.save_configs()
        self.refresh_list()

    def select_config(self, index):
        if self.is_connected and index != self.selected_index:
            tkmb.showwarning("Warning", "Please disconnect before switching servers.")
            return

        self.selected_index = index
        self.refresh_list()

    def run_ping_check(self):
        """Runs the Non-Blocking Ping test on the selected config."""
        if self.selected_index < 0 or self.is_pinging: return
        threading.Thread(target=self._single_ping_logic, daemon=True).start()

    def run_ping_all(self):
        """Runs the Ping test for all loaded configs concurrently."""
        if not self.configs or self.is_pinging: return
        threading.Thread(target=self._ping_all_logic, daemon=True).start()

    def _execute_ping(self, cfg, offset=0):
        """Core method that pings a single configuration item using unique ports."""
        self.log(f"Starting Ping Test: {cfg['alias']}")
        
        # Base ports + offset to avoid conflicts when running concurrently
        socks_pt = 20808 + (offset * 2)
        http_pt = 20809 + (offset * 2)
        cfg_file = f"ping_config_{socks_pt}.json"
        log_file = f"ping_log_{socks_pt}.txt"
        
        runner = XrayRunner(config_filename=cfg_file, log_filename=log_file)
        
        try:
            config_json = generate_xray_config(
                cfg['outbound'], 
                socks_port=socks_pt, 
                http_port=http_pt, 
                enable_mux=False  # Ping tests should always avoid Mux to prevent false negatives
            )
            with open(cfg_file, "w") as f:
                f.write(config_json)

            if runner.start():
                time.sleep(2) 
                proxies = {'http': f'http://127.0.0.1:{http_pt}', 'https': f'http://127.0.0.1:{http_pt}'}
                start_time = time.time()
                try:
                    resp = requests.get("http://www.google.com/generate_204", proxies=proxies, timeout=10)
                    latency = int((time.time() - start_time) * 1000)
                    if resp.status_code in [200, 204]:
                         self.log(f"Ping Success [{cfg['alias']}]: {latency}ms")
                         cfg['last_ping'] = latency
                    else:
                         cfg['last_ping'] = "Fail"
                except Exception as e:
                    cfg['last_ping'] = "Fail"
            else:
                cfg['last_ping'] = "Fail"
        except Exception as e:
             self.log(f"Ping Exception [{cfg['alias']}]: {e}")
             cfg['last_ping'] = "Fail"
        finally:
            runner.stop()
            if os.path.exists(cfg_file):
                try: os.remove(cfg_file)
                except: pass
            
            cfg['is_pinging_active'] = False
            self.save_configs()
            
            # Safe UI Update from thread
            def update_ui():
                try: self.refresh_list()
                except: pass
            self.after(0, update_ui)

    def _single_ping_logic(self):
        self.is_pinging = True
        self.btn_ping.configure(state="disabled", text="Pinging...")
        self.btn_ping_all.configure(state="disabled")
        
        cfg = self.configs[self.selected_index]
        cfg['is_pinging_active'] = True
        self.after(0, self.refresh_list)
        
        try:
            self._execute_ping(cfg, offset=0)
        finally:
            self.is_pinging = False
            self.after(0, lambda: self.btn_ping.configure(state="normal", text="Ping Test"))
            self.after(0, self.refresh_list)

    def _ping_all_logic(self):
        self.is_pinging = True
        self.btn_ping.configure(state="disabled")
        self.btn_ping_all.configure(state="disabled", text="Pinging All...")
        
        # Mark all as active to trigger UI
        for cfg in self.configs:
            cfg['is_pinging_active'] = True
        self.after(0, self.refresh_list)
        
        try:
            # Run concurrently with up to 10 workers to prevent system overload
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(self.configs), 10)) as executor:
                futures = []
                for i, cfg in enumerate(self.configs):
                    futures.append(executor.submit(self._execute_ping, cfg, i))
                
                # Wait for all to finish
                concurrent.futures.wait(futures)
        finally:
            self.is_pinging = False
            self.after(0, lambda: self.btn_ping_all.configure(state="normal", text="Ping All"))
            self.after(0, self.refresh_list)


    def toggle_connection(self):
        if self.is_connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        if self.selected_index < 0: return
        
        cfg = self.configs[self.selected_index]
        self.log(f"Connecting to {cfg['alias']}...")
        
        self.btn_connect.configure(state="disabled", text="Connecting...")

        try:
            # Generate config for MAIN instance
            config_json = generate_xray_config(cfg['outbound'], enable_mux=self.mux_switch.get())
            with open("config.json", "w") as f:
                f.write(config_json)

            if self.xray_main.start():
                self.log("Core Started successfully.")
                time.sleep(1) # Let core bind ports
                set_system_proxy(True)
                self.log("System Windows Proxy enabled.")
                
                self.is_connected = True
                
                # Update UI
                self.btn_connect.configure(
                    state="normal", text="Disconnect", 
                    fg_color="#ff4444", hover_color="#cc0000"
                )
                self.mux_switch.configure(state="disabled")
                self.status_dot.configure(text_color="#00ff00")
                self.status_label.configure(text="Connected")
                self.log(f"VPN Active: {cfg['alias']}")
                
                self.refresh_list() # Redraw to show green active card
            else:
                self.log("Error: Failed to start Xray core.")
                self.btn_connect.configure(state="normal", text="Connect")
                self.mux_switch.configure(state="normal")
        except Exception as e:
            self.log(f"Connection Exception: {e}")
            self.btn_connect.configure(state="normal", text="Connect")
            self.mux_switch.configure(state="normal")

    def disconnect(self):
        self.log("Disconnecting...")
        set_system_proxy(False)
        self.xray_main.stop()
        self.is_connected = False
        
        # Update UI
        self.btn_connect.configure(
            text="Connect", fg_color=["#3B8ED0", "#1F6AA5"], hover_color=["#36719F", "#144870"]
        )
        self.mux_switch.configure(state="normal")
        self.status_dot.configure(text_color="gray")
        self.status_label.configure(text="Disconnected")
        self.log("VPN Disconnected.")
        
        self.refresh_list()

    def on_closing(self):
        self.log("Shutting down...")
        if self.is_connected:
            set_system_proxy(False)
        self.xray_main.stop()
        self.xray_ping.stop()
        self.destroy()

if __name__ == "__main__":
    # Ensure appearance mode is set right before initialization
    ctk.set_appearance_mode("Dark")
    app = BabyVPNApp()
    app.mainloop()
