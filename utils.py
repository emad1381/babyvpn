import winreg
import ctypes
import os
import json
import base64
import urllib.parse
import re

# --- Proxy Management ---

def set_system_proxy(enable=True, server="127.0.0.1:10809"):
    """
    Sets or unsets the Windows system proxy.
    """
    try:
        INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
            0, winreg.KEY_ALL_ACCESS)

        if enable:
            # Disable Auto Detect and Auto Config URL to avoid conflicts
            try: winreg.DeleteValue(INTERNET_SETTINGS, 'AutoConfigURL')
            except FileNotFoundError: pass
            
            # Disable AutoDetect (Usually handled by 'ProxyEnable' but good to be sure if key exists)
            # winreg.SetValueEx(INTERNET_SETTINGS, 'AutoDetect', 0, winreg.REG_DWORD, 0)
            
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyServer', 0, winreg.REG_SZ, server)
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyOverride', 0, winreg.REG_SZ, '<local>')
        else:
            winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
    
        winreg.CloseKey(INTERNET_SETTINGS)
        
        # Notify the system that settings have changed
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception as e:
        print(f"Error setting proxy: {e}")

# --- Config Parsing (VLESS/VMESS) ---

def parse_vmess(link):
    """Parses a vmess:// link and returns (outbound_config, alias)."""
    if not link.startswith("vmess://"):
        return None, None
    
    try:
        b64 = link[8:]
        # Fix padding if necessary
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        json_str = base64.b64decode(b64).decode('utf-8')
        data = json.loads(json_str)
        
        # Extract params
        add = data.get("add")
        port = int(data.get("port"))
        uuid = data.get("id")
        aid = int(data.get("aid", 0))
        scy = data.get("scy", "auto")
        net = data.get("net", "tcp")
        tls = data.get("tls", "none")
        host = data.get("host", "")
        sni = data.get("sni", "")
        path = data.get("path", "/")
        alpn = data.get("alpn", "")
        fp = data.get("fp", "")
        type_header = data.get("type", "none")
        
        # Helper to extract name
        alias = data.get("ps", "VMess Config")

        if host and not sni:
            sni = host

        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": add,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "alterId": aid,
                        "security": scy,
                        "level": 0
                    }]
                }]
            },
            "streamSettings": {
                "network": net,
                "security": tls
            }
        }
        
        # TLS
        if tls == "tls":
            tls_settings = {
                "serverName": sni,
                "allowInsecure": False
            }
            if alpn:
                tls_settings["alpn"] = alpn.split(",")
            if fp:
                tls_settings["fingerprint"] = fp
            outbound["streamSettings"]["tlsSettings"] = tls_settings

        # Transport
        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": path,
                "headers": {
                    "Host": host if host else sni
                }
            }
        elif net == "xhttp":
            outbound["streamSettings"]["xhttpSettings"] = {
                "path": path,
                "host": host if host else sni
            }
        elif net == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": path
            }
        elif net == "tcp":
            if type_header == "http":
                outbound["streamSettings"]["tcpSettings"] = {
                    "header": {
                        "type": "http",
                        "request": {
                            "headers": {
                                "Host": [host] if host else []
                            }
                        }
                    }
                }
        elif net == "kcp":
            outbound["streamSettings"]["kcpSettings"] = {
                "header": {
                    "type": type_header
                },
                "seed": path
            }
        elif net in ["h2", "http"]:
            outbound["streamSettings"]["httpSettings"] = {
                "path": path,
                "host": [host] if host else [sni] if sni else []
            }
        elif net == "quic":
            outbound["streamSettings"]["quicSettings"] = {
                "security": data.get("scy", "none"),
                "key": path,
                "header": {
                    "type": type_header
                }
            }
        elif net == "httpupgrade":
            outbound["streamSettings"]["httpupgradeSettings"] = {
                "path": path,
                "host": host if host else sni
            }

        return outbound, alias
        
    except Exception as e:
        print(f"Error parsing VMESS: {e}")
        return None, None

def parse_vless(link):
    """Parses a vless:// link and returns (outbound, alias)."""
    if not link.startswith("vless://"):
        return None, None
        
    try:
        parsed = urllib.parse.urlparse(link)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port
        
        # Helper to extract name
        alias = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLess Config"
        
        params = urllib.parse.parse_qs(parsed.query)
        
        # Extract params
        net = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", [""])[0]
        alpn = params.get("alpn", [""])[0]
        service_name = params.get("serviceName", [""])[0]
        header_type = params.get("headerType", ["none"])[0]
        mode = params.get("mode", ["auto"])[0]
        
        if host and not sni:
            sni = host

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "level": 0
                    }]
                }]
            },
            "streamSettings": {
                "network": net,
                "security": security
            }
        }

        # TLS
        if security == "tls":
            tls_settings = {
                "serverName": sni,
                "allowInsecure": False
            }
            if alpn:
                tls_settings["alpn"] = alpn.split(",")
            if fp:
                tls_settings["fingerprint"] = fp
            outbound["streamSettings"]["tlsSettings"] = tls_settings
        
        # Transport
        if net == "ws":
             outbound["streamSettings"]["wsSettings"] = {
                "path": path,
                 "headers": {
                    "Host": host if host else sni
                 }
            }
        elif net == "xhttp":
             outbound["streamSettings"]["xhttpSettings"] = {
                "mode": mode,
                "path": path,
                "host": host if host else sni
            }
        elif net == "grpc":
             outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": service_name
            }
        elif net == "tcp":
            if header_type == "http":
                outbound["streamSettings"]["tcpSettings"] = {
                    "header": {
                        "type": "http",
                        "request": {
                            "headers": {
                                "Host": [host] if host else []
                            }
                        }
                    }
                }
        elif net == "kcp":
            outbound["streamSettings"]["kcpSettings"] = {
                "header": {
                    "type": header_type
                },
                "seed": params.get("seed", [""])[0] or path
            }
        elif net in ["h2", "http"]:
            outbound["streamSettings"]["httpSettings"] = {
                "path": path,
                "host": [host] if host else [sni] if sni else []
            }
        elif net == "quic":
            outbound["streamSettings"]["quicSettings"] = {
                "security": params.get("quicSecurity", ["none"])[0],
                "key": params.get("key", [""])[0],
                "header": {
                    "type": header_type
                }
            }
        elif net == "httpupgrade":
            outbound["streamSettings"]["httpupgradeSettings"] = {
                "path": path,
                "host": host if host else sni
            }
            
        return outbound, alias

    except Exception as e:
        print(f"Error parsing VLESS: {e}")
        return None, None

def parse_trojan(link):
    """Parses a trojan:// link and returns (outbound, alias)."""
    if not link.startswith("trojan://"):
        return None, None
        
    try:
        parsed = urllib.parse.urlparse(link)
        password = parsed.username
        address = parsed.hostname
        port = parsed.port
        
        alias = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan Config"
        
        params = urllib.parse.parse_qs(parsed.query)
        
        net = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", [""])[0]
        alpn = params.get("alpn", [""])[0]
        service_name = params.get("serviceName", [""])[0]
        header_type = params.get("headerType", ["none"])[0]
        mode = params.get("mode", ["auto"])[0]
        
        if host and not sni:
            sni = host

        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": address,
                    "port": port,
                    "password": password,
                    "level": 0
                }]
            },
            "streamSettings": {
                "network": net,
                "security": security
            }
        }

        # TLS
        if security == "tls":
            tls_settings = {
                "serverName": sni,
                "allowInsecure": False
            }
            if alpn:
                tls_settings["alpn"] = alpn.split(",")
            if fp:
                tls_settings["fingerprint"] = fp
            outbound["streamSettings"]["tlsSettings"] = tls_settings
        
        # Transport
        if net == "ws":
             outbound["streamSettings"]["wsSettings"] = {
                "path": path,
                 "headers": {
                    "Host": host if host else sni
                 }
            }
        elif net == "xhttp":
             outbound["streamSettings"]["xhttpSettings"] = {
                "mode": mode,
                "path": path,
                "host": host if host else sni
            }
        elif net == "grpc":
             outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": service_name
            }
        elif net == "tcp":
            if header_type == "http":
                outbound["streamSettings"]["tcpSettings"] = {
                    "header": {
                        "type": "http",
                        "request": {
                            "headers": {
                                "Host": [host] if host else []
                            }
                        }
                    }
                }
        elif net == "kcp":
            outbound["streamSettings"]["kcpSettings"] = {
                "header": {
                    "type": header_type
                },
                "seed": params.get("seed", [""])[0] or path
            }
        elif net in ["h2", "http"]:
            outbound["streamSettings"]["httpSettings"] = {
                "path": path,
                "host": [host] if host else [sni] if sni else []
            }
        elif net == "quic":
            outbound["streamSettings"]["quicSettings"] = {
                "security": params.get("quicSecurity", ["none"])[0],
                "key": params.get("key", [""])[0],
                "header": {
                    "type": header_type
                }
            }
        elif net == "httpupgrade":
            outbound["streamSettings"]["httpupgradeSettings"] = {
                "path": path,
                "host": host if host else sni
            }
            
        return outbound, alias

    except Exception as e:
        print(f"Error parsing Trojan: {e}")
        return None, None

def generate_xray_config(outbound_config, socks_port=10808, http_port=10809, enable_mux=False):
    """Generates the full config.json content for Xray."""
    if not outbound_config:
        return None
        
    if enable_mux and "mux" not in outbound_config.get("streamSettings", {}):
        outbound_config["mux"] = {
            "enabled": True,
            "concurrency": 8
        }

    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                },
                "tag": "socks-in"
            },
            {
                "port": http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                },
                "tag": "http-in"
            }
        ],
        "outbounds": [
            outbound_config,
            {
                "protocol": "freedom",
                "tag": "direct",
                "settings": {}
            }
        ],
        "dns": {
            "servers": [
                "1.1.1.1",
                "8.8.8.8",
                "localhost"
            ]
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                 {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": ["127.0.0.1/32", "::1/128"]
                }
            ]
        }
    }
    return json.dumps(config, indent=2)
