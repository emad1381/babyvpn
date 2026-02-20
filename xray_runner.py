import subprocess
import psutil
import os
import time
import sys
class XrayRunner:
    def __init__(self, config_filename="config.json", log_filename="xray_log.txt"):
        # Determine path to xray.exe and config.json
        if getattr(sys, 'frozen', False):
            # Running as compiled exe
            base_path = os.path.dirname(sys.executable)
        else:
            # Running as script
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        self.xray_path = os.path.join(base_path, "xray.exe")
        self.config_path = os.path.join(base_path, config_filename)
        self.log_filename = log_filename
        self.process = None

    def start(self):
        """Starts the xray process."""
        if self.is_running():
            print("Xray is already running.")
            return

        if not os.path.exists(self.xray_path):
            raise FileNotFoundError(f"Xray executable not found at: {self.xray_path}")

        try:
            # Hide the console window
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            # Redirect stdout/stderr to a file for debugging
            self.log_file = open(self.log_filename, "w")
            self.process = subprocess.Popen(
                [self.xray_path, "-c", self.config_path],
                startupinfo=startupinfo,
                stdout=self.log_file,
                stderr=self.log_file
            )
            print(f"Xray started with PID: {self.process.pid} (Config: {self.config_path})")
            return True
        except Exception as e:
            print(f"Failed to start Xray: {e}")
            return False

    def stop(self):
        """Stops the xray process."""
        if self.process:
            self.process.terminate()
            self.process = None
            print("Xray stopped.")
        
        if hasattr(self, 'log_file') and self.log_file:
            self.log_file.close()
            self.log_file = None
        
        # We don't indiscriminately kill ALL xray.exe anymore,
        # because we might be running multiple instances (Main + Ping).
        # We only terminate the process we started.

    def is_running(self):
        """Checks if the process is running."""
        if self.process is None:
            return False
        return self.process.poll() is None
