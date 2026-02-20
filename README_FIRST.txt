# Important Instructions for Baby VPN

Your executable file is located in the `dist` folder: `BabyVPN.exe`.

## How to Run:
Since this application relies on the Xray Core, you MUST do the following:

1. Copy `BabyVPN.exe` from the `dist` folder to a new folder (e.g., inside `C:\BabyVPN`).
2. **Download or Copy `xray.exe`** and place it in the **SAME FOLDER** as `BabyVPN.exe`.
   - Ensure other Xray core files like `geosite.dat` and `geoip.dat` are NOT strictly required since we removed those dependencies in the code, but having them doesn't hurt.
3. Run `BabyVPN.exe`.

The application will look for `xray.exe` right next to itself. If it's missing, it won't connect.
