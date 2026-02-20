import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_v2ray/flutter_v2ray.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'config_parser.dart';

void main() {
  runApp(const BabyVPNApp());
}

class BabyVPNApp extends StatelessWidget {
  const BabyVPNApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Baby VPN',
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF1E1E24),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00B4D8),
          surface: Color(0xFF2B2D42),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1E1E24),
          elevation: 0,
        ),
      ),
      home: const MainScreen(),
    );
  }
}

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  late final FlutterV2ray _flutterV2ray;

  @override
  void initState() {
    super.initState();
    _flutterV2ray = FlutterV2ray(
      onStatusChanged: (status) {
        setState(() {
          _v2rayStatus = status;
          _isConnected = status.state == 'CONNECTED';
        });
      },
    );
    _initV2ray();
    _loadConfigs();
  }

  List<Map<String, dynamic>> _configs = [];
  int _selectedIndex = -1;
  bool _isConnected = false;
  V2RayStatus _v2rayStatus = V2RayStatus();
  bool _enableMux = false;

  Future<void> _initV2ray() async {
    await _flutterV2ray.initializeV2Ray();
  }

  Future<void> _loadConfigs() async {
    final prefs = await SharedPreferences.getInstance();
    final String? confStr = prefs.getString('configs');
    if (confStr != null) {
      setState(() {
        List<dynamic> parsed = jsonDecode(confStr);
        _configs = parsed.map((e) => Map<String, dynamic>.from(e)).toList();
      });
    }
  }

  Future<void> _saveConfigs() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('configs', jsonEncode(_configs));
  }

  void _pasteConfig() async {
    ClipboardData? data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data == null || data.text == null || data.text!.isEmpty) {
      _showSnack("Clipboard is empty!");
      return;
    }

    String text = data.text!.trim();
    List<String> lines = text.split(RegExp(r'[\n\r]+'));
    int addedCount = 0;
    
    for (String line in lines) {
      line = line.trim();
      if (line.isEmpty) continue;
      
      Map<String, dynamic>? parsed;
      if (line.startsWith("vless://")) {
        parsed = ConfigParser.parseVless(line);
      } else if (line.startsWith("vmess://")) {
        parsed = ConfigParser.parseVmess(line);
      } else if (line.startsWith("trojan://")) {
        parsed = ConfigParser.parseTrojan(line);
      }
      
      if (parsed != null) {
        setState(() {
          _configs.add(parsed!);
        });
        addedCount++;
      }
    }

    if (addedCount > 0) {
      _saveConfigs();
      _showSnack("Added $addedCount configuration(s).");
    } else {
      _showSnack("Failed to parse any valid configuration from clipboard.");
    }
  }

  void _toggleConnection() async {
    if (_isConnected) {
      await _flutterV2ray.stopV2Ray();
    } else {
      if (_selectedIndex < 0 || _selectedIndex >= _configs.length) {
        _showSnack("Please select a server first.");
        return;
      }
      
      var cfg = _configs[_selectedIndex];
      var outbound = Map<String, dynamic>.from(cfg['outbound']);
      
      if (_enableMux && !outbound.containsKey("mux")) {
          outbound["mux"] = {
              "enabled": true,
              "concurrency": 8
          };
      }

      var fullConfig = {
        "log": {"loglevel": "warning"},
        "inbounds": [
          {
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true}
          },
          {
            "port": 10809,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {}
          }
        ],
        "outbounds": [
          outbound,
          {"protocol": "freedom", "tag": "direct"}
        ],
        "dns": {
            "servers": ["1.1.1.1", "8.8.8.8", "localhost"]
        }
      };

      await _flutterV2ray.startV2Ray(
        remark: cfg['alias'],
        config: jsonEncode(fullConfig),
        proxyOnly: false,
      );
    }
  }

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg), behavior: SnackBarBehavior.floating));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Baby VPN', style: TextStyle(fontWeight: FontWeight.bold, color: Color(0xFF00B4D8))),
        actions: [
          IconButton(
            icon: const Icon(Icons.content_paste, color: Colors.white),
            onPressed: _pasteConfig,
            tooltip: "Paste Config",
          )
        ],
      ),
      body: Column(
        children: [
          _buildStatusHeader(),
          Expanded(
            child: _configs.isEmpty
                ? const Center(child: Text("No servers added yet.\nCopy a Vmess/Vless/Trojan link and click Paste.", textAlign: TextAlign.center, style: TextStyle(color: Colors.grey)))
                : ListView.builder(
                    padding: const EdgeInsets.all(12),
                    itemCount: _configs.length,
                    itemBuilder: (context, index) {
                      final cfg = _configs[index];
                      final isSelected = _selectedIndex == index;
                      return Card(
                        color: isSelected ? const Color(0xFF3B4058) : const Color(0xFF2B2D42),
                        shape: RoundedRectangleBorder(
                          side: BorderSide(color: isSelected ? const Color(0xFF00B4D8) : Colors.transparent, width: 2),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        margin: const EdgeInsets.only(bottom: 12),
                        child: ListTile(
                          title: Text(cfg['alias'] ?? 'Unknown', style: const TextStyle(fontWeight: FontWeight.bold)),
                          subtitle: Text((cfg['outbound']['protocol'] ?? '').toUpperCase()),
                          trailing: IconButton(
                            icon: const Icon(Icons.delete, color: Colors.white54),
                            onPressed: () {
                              if (_isConnected && isSelected) {
                                _showSnack("Cannot delete active connection.");
                                return;
                              }
                              setState(() {
                                _configs.removeAt(index);
                                if (_selectedIndex == index) _selectedIndex = -1;
                                else if (_selectedIndex > index) _selectedIndex--;
                              });
                              _saveConfigs();
                            },
                          ),
                          onTap: () {
                            if (_isConnected) {
                              _showSnack("Disconnect before switching servers.");
                              return;
                            }
                            setState(() {
                              _selectedIndex = index;
                            });
                          },
                        ),
                      );
                    },
                  ),
          )
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _toggleConnection,
        backgroundColor: _isConnected ? Colors.redAccent : const Color(0xFF00B4D8),
        icon: Icon(_isConnected ? Icons.stop : Icons.rocket_launch, color: Colors.white),
        label: Text(_isConnected ? 'Stop' : 'Connect', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
      ),
      floatingActionButtonLocation: FloatingActionButtonLocation.centerFloat,
    );
  }

  Widget _buildStatusHeader() {
    return Container(
      padding: const EdgeInsets.all(20),
      margin: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF2B2D42),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.circle, size: 16, color: _isConnected ? Colors.greenAccent : Colors.grey),
              const SizedBox(width: 8),
              Text(
                _isConnected ? "Connected" : "Disconnected",
                style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
            ],
          ),
          if (_isConnected) ...[
            const SizedBox(height: 12),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                Text("↓ ${_v2rayStatus.downloadSpeed}", style: const TextStyle(color: Colors.greenAccent)),
                Text("↑ ${_v2rayStatus.uploadSpeed}", style: const TextStyle(color: Colors.blueAccent)),
              ],
            )
          ],
          const Divider(height: 30, color: Colors.white24),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text("Enable Mux (Faster TCP)"),
              Switch(
                value: _enableMux,
                onChanged: _isConnected ? null : (val) {
                  setState(() { _enableMux = val; });
                },
                activeColor: const Color(0xFF00B4D8),
              )
            ],
          )
        ],
      ),
    );
  }
}
