import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:dotted_border/dotted_border.dart';
import 'package:flutter/material.dart';

class VirusScannerPage extends StatelessWidget {
  const VirusScannerPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildSidebarPanel(context, 3),
            Expanded(
              child: Column(
                children: [
                  buildTopNavbar(context, 'Virus Scanner'),
                  Expanded(child: _VirusScannerContent()),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _VirusScannerContent extends StatefulWidget {
  const _VirusScannerContent({super.key});

  @override
  State<_VirusScannerContent> createState() => __VirusScannerContentState();
}

class __VirusScannerContentState extends State<_VirusScannerContent> {
  String? selectedFileName;
  bool isHovered = false;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      child: Padding(
        padding: const EdgeInsets.all(40),
        child: Column(
          children: [
            Container(
              decoration: BoxDecoration(
                color: const Color(0xFF0F1420),
                borderRadius: BorderRadius.circular(12),
              ),
              width: 1000,
              height: 750,
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 12.0),
                    child: Center(
                      child: Text(
                        'Virus & Malware Scanner',
                        style: TextStyle(
                          color: const Color.fromARGB(255, 238, 238, 238),
                          fontSize: 24,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  Center(
                    child: Text(
                      'Upload a file or enter a URL to scan for threats',
                      style: TextStyle(
                        color: Colors.white70,
                        fontSize: 18,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  MouseRegion(
                    onEnter: (_) => setState(() => isHovered = true),
                    onExit: (_) => setState(() => isHovered = false),
                    child: DottedBorder(
                      options: RoundedRectDottedBorderOptions(
                        dashPattern: [6, 4],
                        strokeWidth: 2,
                        color: isHovered ? Colors.cyan : Colors.white38,
                        radius: Radius.circular(12),
                      ),
                      child: Container(
                        height: 350,
                        width: 800,
                        child: Center(
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Container(
                                width: 80,
                                height: 80,
                                decoration: BoxDecoration(
                                  color: Colors.cyan.withOpacity(0.2),
                                  shape: BoxShape.circle,
                                ),
                                child: Icon(
                                  Icons.cloud_upload_outlined,
                                  size: 48,
                                  color: Colors.cyan,
                                ),
                              ),
                              SizedBox(height: 16),
                              Text(
                                "Drop files here or click to browse",
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 18,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              SizedBox(height: 16),
                              Text(
                                'Maximum file size: 256 MB',
                                style: TextStyle(
                                  color: Colors.white70,
                                  fontSize: 14,
                                ),
                              ),
                              SizedBox(height: 24),
                              Container(
                                width: 120,
                                height: 50,
                                child: TextButton(
                                  style: TextButton.styleFrom(
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(12),
                                    ),
                                    backgroundColor: Colors.cyan,
                                    foregroundColor: Colors.white,
                                  ),
                                  onPressed: () {},
                                  child: Text(
                                    'Select File',
                                    style: TextStyle(
                                      color: Colors.white,
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ),
                              ),
                              if (selectedFileName != null) ...[
                                SizedBox(height: 12),
                                Text(
                                  'File: $selectedFileName',
                                  style: TextStyle(
                                    color: Colors.cyan,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),

                  SizedBox(height: 24),
                  Container(
                    width: 800,
                    height: 60,
                    child: TextField(
                      decoration: InputDecoration(
                        hintText: 'Or enter a URL to scan...',
                        hintStyle: TextStyle(color: Colors.white54),
                        filled: true,
                        fillColor: const Color.fromARGB(255, 33, 37, 52),
                        contentPadding: EdgeInsets.symmetric(
                          horizontal: 16,
                          vertical: 20,
                        ),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(12),
                          borderSide: BorderSide(color: Colors.cyan, width: 1),
                        ),
                        enabledBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(12),
                          borderSide: BorderSide(
                            color: Colors.white24,
                            width: 1,
                          ),
                        ),
                        prefixIcon: Icon(Icons.link, color: Colors.white70),
                      ),
                      style: TextStyle(color: Colors.white),
                    ),
                  ),
                  SizedBox(height: 16),
                  Container(
                    width: 800,
                    height: 50,
                    child: TextButton(
                      style: TextButton.styleFrom(
                        backgroundColor: Colors.cyan,
                        foregroundColor: Colors.white,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                      onPressed: () {},
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.search),
                          SizedBox(width: 8),
                          Text('Scan Now'),
                        ],
                      ),
                    ),
                  ),
                  SizedBox(height: 24),
                  Container(
                    width: 800,
                    padding: EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Color(0xFF1A3A52),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      children: [
                        Icon(Icons.note, color: Colors.cyan, size: 20),
                        SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            'Note: This scanner uses VirusTotal API. Connect your API key in Settings to enable real scanning.',
                            style: TextStyle(
                              color: Colors.white70,
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
