import 'package:cybersentinel/auth/require_auth.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/widgets/shared/page_header.dart';
import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:dotted_border/dotted_border.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

class VirusScannerPage extends StatelessWidget {
  const VirusScannerPage({super.key});

  @override
  Widget build(BuildContext context) {
    return RequireAuth(
      child: Scaffold(
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
                    Expanded(child: const VirusScannerContent()),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class VirusScannerContent extends StatefulWidget {
  const VirusScannerContent({super.key});

  @override
  State<VirusScannerContent> createState() => _VirusScannerContentState();
}

class _VirusScannerContentState extends State<VirusScannerContent> {
  String? selectedFileName;
  PlatformFile? selectedFile;
  bool isHovered = false;
  bool _scanning = false;
  Map<String, dynamic>? _result;
  String? _scanKind;
  final _urlController = TextEditingController();

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(withData: true);
    if (result != null && result.files.isNotEmpty) {
      setState(() {
        selectedFile = result.files.first;
        selectedFileName = selectedFile!.name;
        _urlController.clear();
        _result = null;
      });
    }
  }

  String _normalizeUrl(String raw) {
    final value = raw.trim();
    if (value.isEmpty) return value;
    if (value.startsWith('http://') || value.startsWith('https://')) {
      return value;
    }
    return 'https://$value';
  }

  Future<void> _scan() async {
    if (!ApiConfig.isConfigured) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please sign in to continue')),
      );
      return;
    }

    final urlInput = _urlController.text.trim();
    final hasUrl = urlInput.isNotEmpty;
    final hasFile = selectedFile != null;

    if (!hasUrl && !hasFile) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a URL or select a file to scan')),
      );
      return;
    }

    setState(() {
      _scanning = true;
      _result = null;
      _scanKind = null;
    });

    try {
      final Map<String, dynamic> data;
      if (hasUrl) {
        data = await ApiService.instance.scanUrl(_normalizeUrl(urlInput));
        _scanKind = 'url';
      } else {
        data = await ApiService.instance.scanFile(selectedFile!);
        _scanKind = 'file';
      }

      if (!mounted) return;
      setState(() {
        _result = data;
        _scanning = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _scanning = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
      );
    }
  }

  Color _threatColor(String level) {
    switch (level.toLowerCase()) {
      case 'malicious':
      case 'high':
      case 'critical':
        return AppColors.redLight;
      case 'suspicious':
      case 'medium':
        return AppColors.amber;
      case 'harmless':
      case 'low':
      case 'clean':
        return AppColors.greenLight;
      default:
        return AppColors.textMuted;
    }
  }

  Widget _resultStat(String label, String value, {Color? valueColor}) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: AppColors.alertItemBg,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.borderElevated),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: const TextStyle(color: AppColors.textDim, fontSize: 11)),
            const SizedBox(height: 4),
            Text(
              value,
              style: TextStyle(
                color: valueColor ?? AppColors.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildScanResult() {
    final result = _result!;
    final threatLevel = result['threat_level']?.toString() ?? 'unknown';
    final threatColor = _threatColor(threatLevel);
    final malicious = result['malicious_count'] ?? 0;
    final suspicious = result['suspicious_count'] ?? 0;
    final harmless = result['harmless_count'] ?? 0;
    final undetected = result['undetected_count'] ?? 0;
    final totalEngines = result['total_engines'] ?? 0;
    final threatScore = result['threat_score'] ?? 0;
    final scanType = result['scan_type']?.toString() ?? _scanKind ?? '-';
    final providerStatus = result['provider_status']?.toString() ?? '-';
    final lookupKey = result['lookup_key']?.toString();
    final ip = result['ip']?.toString();
    final cached = result['cached'] == true;
    final scannedAt = result['scanned_at']?.toString();

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.alertItemBg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.borderElevated),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'Scan result',
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 18,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: threatColor.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: threatColor.withValues(alpha: 0.35)),
                ),
                child: Text(
                  threatLevel.toUpperCase(),
                  style: TextStyle(color: threatColor, fontSize: 12, fontWeight: FontWeight.w700),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              _resultStat('Threat score', '$threatScore', valueColor: threatColor),
              const SizedBox(width: 8),
              _resultStat('Engines', '$malicious / $totalEngines malicious', valueColor: AppColors.redLight),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              _resultStat('Suspicious', '$suspicious', valueColor: AppColors.amber),
              const SizedBox(width: 8),
              _resultStat('Harmless', '$harmless', valueColor: AppColors.greenLight),
              const SizedBox(width: 8),
              _resultStat('Undetected', '$undetected'),
            ],
          ),
          const SizedBox(height: 12),
          if (lookupKey != null && lookupKey.isNotEmpty)
            _resultDetailRow('Lookup key', lookupKey),
          if (ip != null && ip.isNotEmpty) _resultDetailRow('Resolved IP', ip),
          _resultDetailRow('Scan type', scanType),
          _resultDetailRow('Provider status', providerStatus),
          _resultDetailRow('Cached result', cached ? 'Yes' : 'No'),
          if (scannedAt != null && scannedAt.isNotEmpty)
            _resultDetailRow('Scanned at', scannedAt),
        ],
      ),
    );
  }

  Widget _resultDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(label, style: const TextStyle(color: AppColors.textDim, fontSize: 12)),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(color: AppColors.textMuted, fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(32),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1000),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const PageHeader(
                title: 'Virus & malware scanner',
                subtitle: 'Scan files and URLs with VirusTotal threat intelligence integration.',
                icon: Icons.bug_report_outlined,
              ),
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF0F1420),
                  borderRadius: BorderRadius.circular(12),
                ),
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
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
                      child: SizedBox(
                        height: 280,
                        width: double.infinity,
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
                              SizedBox(
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
                                  onPressed: _pickFile,
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

                  const SizedBox(height: 24),
                  TextField(
                    controller: _urlController,
                    keyboardType: TextInputType.url,
                    textInputAction: TextInputAction.go,
                    onSubmitted: (_) => _scanning ? null : _scan(),
                    onChanged: (_) {
                      if (selectedFile != null) {
                        setState(() {
                          selectedFile = null;
                          selectedFileName = null;
                        });
                      }
                    },
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
                  const SizedBox(height: 16),
                  SizedBox(
                    width: double.infinity,
                    height: 50,
                    child: TextButton(
                      style: TextButton.styleFrom(
                        backgroundColor: Colors.cyan,
                        foregroundColor: Colors.white,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                      onPressed: _scanning ? null : _scan,
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          if (_scanning)
                            const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                            )
                          else
                            const Icon(Icons.search),
                          const SizedBox(width: 8),
                          Text(_scanning ? 'Scanning...' : 'Scan Now'),
                        ],
                      ),
                    ),
                  ),
                  if (_result != null) ...[
                    const SizedBox(height: 24),
                    _buildScanResult(),
                  ],
                  const SizedBox(height: 24),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(16),
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
                            'Note: URL scans are sent to the backend intel API (VirusTotal). Configure your API key in Settings.',
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
      ),
    );
  }
}
