import 'dart:convert';

class ConfigParser {
  static Map<String, dynamic>? parseVless(String link) {
    if (!link.startsWith("vless://")) return null;
    
    try {
      int hashIndex = link.indexOf('#');
      if (hashIndex != -1) {
        String base = link.substring(0, hashIndex);
        String fragment = link.substring(hashIndex + 1);
        try { fragment = Uri.decodeComponent(fragment); } catch(e) {}
        link = base + '#' + Uri.encodeComponent(fragment);
      }
      final uri = Uri.parse(link);
      final uuid = uri.userInfo;
      final address = uri.host;
      final port = uri.hasPort ? uri.port : 443;
      final alias = uri.fragment.isNotEmpty ? Uri.decodeComponent(uri.fragment) : "VLess Config";

      final net = uri.queryParameters['type'] ?? 'tcp';
      final security = uri.queryParameters['security'] ?? 'none';
      final path = uri.queryParameters['path'] ?? '/';
      final host = uri.queryParameters['host'] ?? '';
      final sniParam = uri.queryParameters['sni'] ?? '';
      final fp = uri.queryParameters['fp'] ?? '';
      final alpnStr = uri.queryParameters['alpn'] ?? '';
      final serviceName = uri.queryParameters['serviceName'] ?? '';
      final headerType = uri.queryParameters['headerType'] ?? 'none';
      final mode = uri.queryParameters['mode'] ?? 'auto';

      final bool allowInsecure = (uri.queryParameters['allowInsecure'] == '1' || uri.queryParameters['allowInsecure'] == 'true' || uri.queryParameters['insecure'] == '1' || uri.queryParameters['insecure'] == 'true');

      final sni = (host.isNotEmpty && sniParam.isEmpty) ? host : sniParam;

      Map<String, dynamic> outbound = {
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
      };

      if (security == "tls") {
        Map<String, dynamic> tlsSettings = {
          "serverName": sni,
          "allowInsecure": allowInsecure
        };
        if (alpnStr.isNotEmpty) tlsSettings["alpn"] = alpnStr.split(",");
        if (fp.isNotEmpty) tlsSettings["fingerprint"] = fp;
        outbound["streamSettings"]["tlsSettings"] = tlsSettings;
      }

      switch (net) {
        case 'ws':
          outbound["streamSettings"]["wsSettings"] = {
            "path": path,
            "headers": { "Host": host.isNotEmpty ? host : sni }
          };
          break;
        case 'xhttp':
          outbound["streamSettings"]["xhttpSettings"] = {
            "mode": mode,
            "path": path,
            "host": host.isNotEmpty ? host : sni
          };
          break;
        case 'grpc':
          outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": serviceName
          };
          break;
        case 'tcp':
          if (headerType == 'http') {
              outbound["streamSettings"]["tcpSettings"] = {
                  "header": {
                      "type": "http",
                      "request": {
                          "headers": {
                              "Host": host.isNotEmpty ? [host] : []
                          }
                      }
                  }
              };
          }
          break;
        case 'kcp':
          outbound["streamSettings"]["kcpSettings"] = {
              "header": { "type": headerType },
              "seed": uri.queryParameters['seed'] ?? path
          };
          break;
        case 'h2':
        case 'http':
          outbound["streamSettings"]["httpSettings"] = {
              "path": path,
              "host": host.isNotEmpty ? [host] : (sni.isNotEmpty ? [sni] : [])
          };
          break;
        case 'quic':
          outbound["streamSettings"]["quicSettings"] = {
              "security": uri.queryParameters['quicSecurity'] ?? 'none',
              "key": uri.queryParameters['key'] ?? '',
              "header": { "type": headerType }
          };
          break;
        case 'httpupgrade':
          outbound["streamSettings"]["httpupgradeSettings"] = {
              "path": path,
              "host": host.isNotEmpty ? host : sni
          };
          break;
      }
      
      return {'outbound': outbound, 'alias': alias};
    } catch (e) {
      print("Error parsing VLESS: $e");
      return null;
    }
  }

  static Map<String, dynamic>? parseTrojan(String link) {
    if (!link.startsWith("trojan://")) return null;
    
    try {
      int hashIndex = link.indexOf('#');
      if (hashIndex != -1) {
        String base = link.substring(0, hashIndex);
        String fragment = link.substring(hashIndex + 1);
        try { fragment = Uri.decodeComponent(fragment); } catch(e) {}
        link = base + '#' + Uri.encodeComponent(fragment);
      }
      final uri = Uri.parse(link);
      final password = uri.userInfo;
      final address = uri.host;
      final port = uri.hasPort ? uri.port : 443;
      final alias = uri.fragment.isNotEmpty ? Uri.decodeComponent(uri.fragment) : "Trojan Config";

      final net = uri.queryParameters['type'] ?? 'tcp';
      final security = uri.queryParameters['security'] ?? 'none';
      final path = uri.queryParameters['path'] ?? '/';
      final host = uri.queryParameters['host'] ?? '';
      final sniParam = uri.queryParameters['sni'] ?? '';
      final fp = uri.queryParameters['fp'] ?? '';
      final alpnStr = uri.queryParameters['alpn'] ?? '';
      final serviceName = uri.queryParameters['serviceName'] ?? '';
      final headerType = uri.queryParameters['headerType'] ?? 'none';
      final mode = uri.queryParameters['mode'] ?? 'auto';

      final bool allowInsecure = (uri.queryParameters['allowInsecure'] == '1' || uri.queryParameters['allowInsecure'] == 'true' || uri.queryParameters['insecure'] == '1' || uri.queryParameters['insecure'] == 'true');

      final sni = (host.isNotEmpty && sniParam.isEmpty) ? host : sniParam;

      Map<String, dynamic> outbound = {
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
      };

      if (security == "tls") {
        Map<String, dynamic> tlsSettings = {
          "serverName": sni,
          "allowInsecure": allowInsecure
        };
        if (alpnStr.isNotEmpty) tlsSettings["alpn"] = alpnStr.split(",");
        if (fp.isNotEmpty) tlsSettings["fingerprint"] = fp;
        outbound["streamSettings"]["tlsSettings"] = tlsSettings;
      }

      switch (net) {
        case 'ws':
          outbound["streamSettings"]["wsSettings"] = {
            "path": path,
            "headers": { "Host": host.isNotEmpty ? host : sni }
          };
          break;
        case 'xhttp':
          outbound["streamSettings"]["xhttpSettings"] = {
            "mode": mode,
            "path": path,
            "host": host.isNotEmpty ? host : sni
          };
          break;
        case 'grpc':
          outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": serviceName
          };
          break;
        case 'tcp':
          if (headerType == 'http') {
              outbound["streamSettings"]["tcpSettings"] = {
                  "header": {
                      "type": "http",
                      "request": {
                          "headers": {
                              "Host": host.isNotEmpty ? [host] : []
                          }
                      }
                  }
              };
          }
          break;
        case 'kcp':
          outbound["streamSettings"]["kcpSettings"] = {
              "header": { "type": headerType },
              "seed": uri.queryParameters['seed'] ?? path
          };
          break;
        case 'h2':
        case 'http':
          outbound["streamSettings"]["httpSettings"] = {
              "path": path,
              "host": host.isNotEmpty ? [host] : (sni.isNotEmpty ? [sni] : [])
          };
          break;
        case 'quic':
          outbound["streamSettings"]["quicSettings"] = {
              "security": uri.queryParameters['quicSecurity'] ?? 'none',
              "key": uri.queryParameters['key'] ?? '',
              "header": { "type": headerType }
          };
          break;
        case 'httpupgrade':
          outbound["streamSettings"]["httpupgradeSettings"] = {
              "path": path,
              "host": host.isNotEmpty ? host : sni
          };
          break;
      }

      return {'outbound': outbound, 'alias': alias};
    } catch (e) {
      print("Error parsing Trojan: $e");
      return null;
    }
  }

  static Map<String, dynamic>? parseVmess(String link) {
    if (!link.startsWith("vmess://")) return null;
    
    try {
      String b64 = link.substring(8);
      int hashIndex = b64.indexOf('#');
      if (hashIndex != -1) b64 = b64.substring(0, hashIndex);
      int qIndex = b64.indexOf('?');
      if (qIndex != -1) b64 = b64.substring(0, qIndex);
      
      // Clean up base64 string
      b64 = b64.replaceAll(RegExp(r'\s+'), '');
      
      // Add missing padding
      int padding = b64.length % 4;
      if (padding > 0) {
        b64 += '=' * (4 - padding);
      }
      
      // Safely decode
      String jsonStr;
      try {
        jsonStr = utf8.decode(base64Decode(b64));
      } catch (e) {
        // Fallback to URL-safe base64 decode if standard fails
        jsonStr = utf8.decode(base64Url.decode(b64));
      }
      
      Map<String, dynamic> data = jsonDecode(jsonStr);

      String add = data["add"]?.toString() ?? "";
      int port = int.tryParse(data["port"]?.toString() ?? "0") ?? 0;
      String uuid = data["id"]?.toString() ?? "";
      String net = data["net"]?.toString() ?? "tcp";
      String typeHeader = data["type"]?.toString() ?? "none";
      String host = data["host"]?.toString() ?? "";
      String path = data["path"]?.toString() ?? "";
      String tls = data["tls"]?.toString() ?? "none";
      String sni = data["sni"]?.toString() ?? "";
      String alpnStr = data["alpn"]?.toString() ?? "";
      String fp = data["fp"]?.toString() ?? "";

      String alias = data["ps"]?.toString() ?? Uri.decodeComponent(data["ps"]?.toString() ?? "VMess Config");

      if (host.isNotEmpty && sni.isEmpty) sni = host;

      Map<String, dynamic> outbound = {
        "protocol": "vmess",
        "settings": {
          "vnext": [{
            "address": add,
            "port": port,
            "users": [{
              "id": uuid,
              "alterId": 0,
              "security": "auto",
              "level": 0
            }]
          }]
        },
        "streamSettings": {
          "network": net,
          "security": tls == "tls" ? "tls" : "none"
        }
      };

      if (tls == "tls") {
        Map<String, dynamic> tlsSettings = {
          "serverName": sni,
          "allowInsecure": false
        };
        if (alpnStr.isNotEmpty) tlsSettings["alpn"] = alpnStr.split(",");
        if (fp.isNotEmpty) tlsSettings["fingerprint"] = fp;
        outbound["streamSettings"]["tlsSettings"] = tlsSettings;
      }

      switch (net) {
        case 'ws':
          outbound["streamSettings"]["wsSettings"] = {
            "path": path,
            "headers": { "Host": host.isNotEmpty ? host : sni }
          };
          break;
        case 'xhttp':
          outbound["streamSettings"]["xhttpSettings"] = {
            "path": path,
            "host": host.isNotEmpty ? host : sni
          };
          break;
        case 'grpc':
          outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": path
          };
          break;
        case 'tcp':
          if (typeHeader == 'http') {
              outbound["streamSettings"]["tcpSettings"] = {
                  "header": {
                      "type": "http",
                      "request": {
                          "headers": {
                              "Host": host.isNotEmpty ? [host] : []
                          }
                      }
                  }
              };
          }
          break;
        case 'kcp':
          outbound["streamSettings"]["kcpSettings"] = {
              "header": { "type": typeHeader },
              "seed": path
          };
          break;
        case 'h2':
        case 'http':
          outbound["streamSettings"]["httpSettings"] = {
              "path": path,
              "host": host.isNotEmpty ? [host] : (sni.isNotEmpty ? [sni] : [])
          };
          break;
        case 'quic':
          outbound["streamSettings"]["quicSettings"] = {
              "security": data["scy"]?.toString() ?? 'none',
              "key": path,
              "header": { "type": typeHeader }
          };
          break;
        case 'httpupgrade':
          outbound["streamSettings"]["httpupgradeSettings"] = {
              "path": path,
              "host": host.isNotEmpty ? host : sni
          };
          break;
      }

      return {'outbound': outbound, 'alias': alias};
    } catch (e) {
      print("Error parsing VMESS: $e");
      return null;
    }
  }
}
