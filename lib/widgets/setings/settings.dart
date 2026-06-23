import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildSidebarPanel(context, 6),
            Expanded(
              child: Column(
                children: [
                  buildTopNavbar(context, 'Settings'),
                  Expanded(child: const SettingsContent()),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class SettingsContent extends StatefulWidget {
  const SettingsContent({super.key});

  @override
  State<SettingsContent> createState() => _SettingsContentState();
}

class _SettingsContentState extends State<SettingsContent> {
  bool backgroundMonitoring = true;
  bool emailAlerts = true;
  bool pushNotifications = false;
  String selectedTheme = 'dark';

  final _baseUrlController = TextEditingController();
  final _apiKeyController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _baseUrlController.text = ApiConfig.baseUrl;
    _apiKeyController.text = ApiConfig.apiKey;
  }

  @override
  void dispose() {
    _baseUrlController.dispose();
    _apiKeyController.dispose();
    super.dispose();
  }

  Future<void> _saveSettings() async {
    await ApiConfig.save(
      url: _baseUrlController.text,
      key: _apiKeyController.text,
    );

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Settings saved')),
    );

    // Quick health check
    try {
      await ApiService.instance.getHealth();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Backend connection OK')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Saved, but backend unreachable: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      child: Padding(
        padding: const EdgeInsets.all(40),
        child: Column(
          children: [
            Container(
              width: 1000,
              decoration: BoxDecoration(
                color: const Color(0xFF0F1420),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF2A2F3E)),
              ),
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Row(
                    children: [
                      Icon(Icons.dns, color: Color(0xFF06B6D4)),
                      SizedBox(width: 8),
                      Text(
                        'Backend Connection',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Connect the app to your CyberSentinel API server',
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 14),
                  ),
                  const Divider(color: Color(0xFF2A2F3E), height: 32),
                  const Text('Backend URL', style: TextStyle(color: Colors.white, fontSize: 14)),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _baseUrlController,
                    decoration: const InputDecoration(
                      filled: true,
                      fillColor: Color(0xFF1A1F2E),
                      hintText: 'http://127.0.0.1:8000',
                      hintStyle: TextStyle(color: Color(0xFF9CA3AF)),
                      border: OutlineInputBorder(borderSide: BorderSide.none),
                    ),
                    style: const TextStyle(color: Color(0xFFD1D5DB)),
                  ),
                  const SizedBox(height: 16),
                  const Text('CyberSentinel API Key', style: TextStyle(color: Colors.white, fontSize: 14)),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _apiKeyController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      filled: true,
                      fillColor: Color(0xFF1A1F2E),
                      hintText: 'Your X-API-Key from .env',
                      hintStyle: TextStyle(color: Color(0xFF9CA3AF)),
                      border: OutlineInputBorder(borderSide: BorderSide.none),
                    ),
                    style: const TextStyle(color: Color(0xFFD1D5DB)),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 25),
            Container(
              width: 1000,
              decoration: BoxDecoration(
                color: const Color(0xFF0F1420),
                borderRadius: BorderRadius.circular(12),
              ),
              padding: const EdgeInsets.all(24.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.key, color: Color(0xFF06B6D4)),
                      const SizedBox(width: 8.0),
                      const Text(
                        'API Keys',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8.0),
                  Text(
                    "Configure external service integrations",
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 14),
                  ),
                  Divider(color: Color(0xFF2A2F3E), height: 32.0),
                  SizedBox(height: 16.0),
                  Text(
                    "VirusTotal API Key",
                    style: TextStyle(color: Colors.white, fontSize: 14),
                  ),
                  SizedBox(height: 8.0),
                  TextField(
                    decoration: InputDecoration(
                      filled: true,
                      fillColor: const Color(0xFF1A1F2E),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                          color: Color(0xFF3A3F4E),
                          width: 1,
                        ),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                          color: Color(0xFF3A3F4E),
                          width: 1,
                        ),
                      ),
                      hintText: 'Enter your VirusTotal API Key',
                      hintStyle: const TextStyle(
                        color: Color(0xFF9CA3AF),
                        fontSize: 16,
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 12,
                      ),
                    ),
                    style: const TextStyle(color: Color(0xFFD1D5DB)),
                  ),
                  Row(
                    children: [
                      Text(
                        'Get your API key from ',
                        style: TextStyle(color: Colors.white54, fontSize: 12),
                      ),
                      Text(
                        "virustotal.com",
                        style: TextStyle(color: Colors.cyan, fontSize: 12),
                      ),
                    ],
                  ),
                  SizedBox(height: 16.0),
                  Text(
                    "GeoIP API Key",
                    style: TextStyle(color: Colors.white, fontSize: 14),
                  ),
                  SizedBox(height: 8.0),
                  TextField(
                    decoration: InputDecoration(
                      filled: true,
                      fillColor: const Color(0xFF1A1F2E),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                          color: Color(0xFF3A3F4E),
                          width: 1,
                        ),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                          color: Color(0xFF3A3F4E),
                          width: 1,
                        ),
                      ),
                      hintText: 'Enter your GeoIP API Key',
                      hintStyle: const TextStyle(
                        color: Color(0xFF9CA3AF),
                        fontSize: 16,
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 12,
                      ),
                    ),
                    style: const TextStyle(color: Color(0xFFD1D5DB)),
                  ),
                  SizedBox(height: 16.0),
                  Text(
                    "AbuseIPDB API Key",
                    style: TextStyle(color: Colors.white, fontSize: 14),
                  ),
                  SizedBox(height: 8.0),
                  TextField(
                    decoration: InputDecoration(
                      filled: true,
                      fillColor: const Color(0xFF1A1F2E),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                          color: Color(0xFF3A3F4E),
                          width: 1,
                        ),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                          color: Color(0xFF3A3F4E),
                          width: 1,
                        ),
                      ),
                      hintText: 'Enter your AbuseIPDB API Key',
                      hintStyle: const TextStyle(
                        color: Color(0xFF9CA3AF),
                        fontSize: 16,
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 12,
                      ),
                    ),
                    style: const TextStyle(color: Color(0xFFD1D5DB)),
                  ),
                ],
              ),
            ),
            SizedBox(height: 25.0),
            Container(
              width: 1000,
              decoration: BoxDecoration(
                color: const Color(0xFF0F1420),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF2A2F3E), width: 1),
              ),
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Padding(
                        padding: const EdgeInsets.only(right: 12.0),
                        child: Icon(
                          Icons.public,
                          color: Color(0xFF06B6D4),
                          size: 20,
                        ),
                      ),
                      Text(
                        'Monitoring',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  SizedBox(height: 6.0),
                  Text(
                    "Configure background monitoring and scanning",
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 12),
                  ),
                  Divider(color: Color(0xFF2A2F3E), height: 24.0),
                  Container(
                    decoration: BoxDecoration(
                      color: const Color(0xFF1A1F2E),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: const Color(0xFF3A3F4E),
                        width: 1,
                      ),
                    ),
                    padding: const EdgeInsets.all(16.0),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Background Monitoring',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 14,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            SizedBox(height: 6.0),
                            Text(
                              'Continuously monitor network traffic for threats',
                              style: TextStyle(
                                color: Color(0xFF9CA3AF),
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                        Switch(
                          value: backgroundMonitoring,
                          onChanged: (value) {
                            setState(() {
                              backgroundMonitoring = value;
                            });
                          },
                          activeThumbColor: Color(0xFF06B6D4),
                          inactiveThumbColor: Color(0xFF6B7280),
                          inactiveTrackColor: Color(0xFF3A3F4E),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(height: 24.0),
            Container(
              width: 1000,
              decoration: BoxDecoration(
                color: const Color(0xFF0F1420),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF2A2F3E), width: 1),
              ),
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Padding(
                        padding: const EdgeInsets.only(right: 12.0),
                        child: Icon(
                          Icons.notifications,
                          color: Color(0xFF06B6D4),
                          size: 20,
                        ),
                      ),
                      Text(
                        'Alerts',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  SizedBox(height: 6.0),
                  Text(
                    "Configure notification preferences",
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 12),
                  ),
                  Divider(color: Color(0xFF2A2F3E), height: 24.0),
                  Container(
                    decoration: BoxDecoration(
                      color: const Color(0xFF1A1F2E),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: const Color(0xFF3A3F4E),
                        width: 1,
                      ),
                    ),
                    padding: const EdgeInsets.all(16.0),
                    margin: const EdgeInsets.only(bottom: 12.0),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Email Alerts',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 14,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            SizedBox(height: 6.0),
                            Text(
                              'Receive threat alerts via email',
                              style: TextStyle(
                                color: Color(0xFF9CA3AF),
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                        Switch(
                          value: emailAlerts,
                          onChanged: (value) {
                            setState(() {
                              emailAlerts = value;
                            });
                          },
                          activeThumbColor: Color(0xFF06B6D4),
                          inactiveThumbColor: Color(0xFF6B7280),
                          inactiveTrackColor: Color(0xFF3A3F4E),
                        ),
                      ],
                    ),
                  ),
                  Container(
                    decoration: BoxDecoration(
                      color: const Color(0xFF1A1F2E),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: const Color(0xFF3A3F4E),
                        width: 1,
                      ),
                    ),
                    padding: const EdgeInsets.all(16.0),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Push Notifications',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 14,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            SizedBox(height: 6.0),
                            Text(
                              'Receive real-time push notifications',
                              style: TextStyle(
                                color: Color(0xFF9CA3AF),
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                        Switch(
                          value: pushNotifications,
                          onChanged: (value) {
                            setState(() {
                              pushNotifications = value;
                            });
                          },
                          activeThumbColor: Color(0xFF06B6D4),
                          inactiveThumbColor: Color(0xFF6B7280),
                          inactiveTrackColor: Color(0xFF3A3F4E),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(height: 24.0),
            Container(
              width: 1000,
              decoration: BoxDecoration(
                color: const Color(0xFF0F1420),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF2A2F3E), width: 1),
              ),
              padding: const EdgeInsets.all(24.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Padding(
                        padding: const EdgeInsets.only(right: 12.0),
                        child: Icon(
                          Icons.brightness_4,
                          color: Color(0xFF06B6D4),
                          size: 20,
                        ),
                      ),
                      Text(
                        'Appearance',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  SizedBox(height: 6.0),
                  Text(
                    "Customize the application theme",
                    style: TextStyle(color: Color(0xFF9CA3AF), fontSize: 14),
                  ),
                  Divider(color: Color(0xFF2A2F3E), height: 24.0),
                  Row(
                    children: [
                      Expanded(
                        child: GestureDetector(
                          onTap: () {
                            setState(() {
                              selectedTheme = 'light';
                            });
                          },
                          child: Container(
                            decoration: BoxDecoration(
                              color: const Color(0xFF1A1F2E),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: selectedTheme == 'light'
                                    ? const Color(0xFF06B6D4)
                                    : const Color(0xFF3A3F4E),
                                width: selectedTheme == 'light' ? 2 : 1,
                              ),
                            ),
                            padding: const EdgeInsets.symmetric(vertical: 16.0),
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(
                                  Icons.wb_sunny,
                                  color: selectedTheme == 'light'
                                      ? Color(0xFF06B6D4)
                                      : Color(0xFF9CA3AF),
                                  size: 20,
                                ),
                                SizedBox(width: 8.0),
                                Text(
                                  'Light',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),
                      SizedBox(width: 12.0),
                      Expanded(
                        child: GestureDetector(
                          onTap: () {
                            setState(() {
                              selectedTheme = 'dark';
                            });
                          },
                          child: Container(
                            decoration: BoxDecoration(
                              color: const Color(0xFF1A1F2E),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: selectedTheme == 'dark'
                                    ? const Color(0xFF06B6D4)
                                    : const Color(0xFF3A3F4E),
                                width: selectedTheme == 'dark' ? 2 : 1,
                              ),
                            ),
                            padding: const EdgeInsets.symmetric(vertical: 16.0),
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(
                                  Icons.nights_stay,
                                  color: selectedTheme == 'dark'
                                      ? Color(0xFF06B6D4)
                                      : Color(0xFF9CA3AF),
                                  size: 20,
                                ),
                                SizedBox(width: 8.0),
                                Text(
                                  'Dark',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            SizedBox(height: 24.0),
            Align(
              alignment: Alignment.centerRight,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF06B6D4),
                  borderRadius: BorderRadius.circular(8),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF06B6D4).withOpacity(0.3),
                      blurRadius: 8,
                      offset: const Offset(0, 4),
                    ),
                  ],
                ),
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    onTap: _saveSettings,
                    borderRadius: BorderRadius.circular(8),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        vertical: 14.0,
                        horizontal: 24.0,
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.save, color: Colors.white, size: 18),
                          SizedBox(width: 8.0),
                          Text(
                            "Save Settings",
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 14,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
