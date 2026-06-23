import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/packet_capture_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/widgets/shared/animated_widgets.dart';
import 'package:cybersentinel/widgets/shared/cyber_card.dart';
import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class PacketTracingContent extends StatelessWidget {
  const PacketTracingContent({super.key});

  @override
  Widget build(BuildContext context) {
    return const PacketTracingScreen();
  }
}

class PacketTracingPage extends StatelessWidget {
  const PacketTracingPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.bg,
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildSidebarPanel(context, 1),
            Expanded(
              child: Column(
                children: [
                  buildTopNavbar(context, 'Packet Tracing'),
                  const Expanded(child: PacketTracingScreen()),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class PacketTracingScreen extends StatefulWidget {
  const PacketTracingScreen({super.key});

  @override
  State<PacketTracingScreen> createState() => _PacketTracingScreenState();
}

class _PacketTracingScreenState extends State<PacketTracingScreen> {
  final _capture = PacketCaptureService.instance;
  final _bpfController = TextEditingController();

  String _selectedProtocol = 'all';
  String _riskLevel = 'all';
  int? _selectedPacketIndex;

  static const _pagePad = 24.0;
  static const _sectionGap = 24.0;
  static const _gridGap = 16.0;

  @override
  void initState() {
    super.initState();
    _bpfController.text = _capture.bpfFilter;
    _capture.addListener(_onCaptureUpdate);
    _capture.loadInterfaces();
  }

  @override
  void dispose() {
    _capture.removeListener(_onCaptureUpdate);
    _bpfController.dispose();
    super.dispose();
  }

  void _onCaptureUpdate() {
    if (!mounted) return;
    final packets = _filteredPackets;
    if (packets.isNotEmpty) {
      if (_selectedPacketIndex == null ||
          _selectedPacketIndex! < 0 ||
          _selectedPacketIndex! >= packets.length) {
        _selectedPacketIndex = 0;
      }
    } else {
      _selectedPacketIndex = null;
    }
    setState(() {});
  }

  String get _streamStatus {
    if (_isCapturing) {
      return 'Capturing packets...';
    }
    return 'Paused';
  }

  bool get _isCapturing => _capture.isCapturing;

  Future<void> _showCaptureSettings() async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.card,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppColors.cardRadius),
          side: const BorderSide(color: AppColors.border),
        ),
        title: const Text(
          'Capture Settings',
          style: TextStyle(color: AppColors.textPrimary, fontSize: 18, fontWeight: FontWeight.w600),
        ),
        content: SizedBox(
          width: 420,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildInterfaceSelector(compact: false),
              const SizedBox(height: 16),
              TextField(
                controller: _bpfController,
                enabled: !_isCapturing,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 14),
                decoration: _fieldDecoration(
                  label: 'BPF Filter',
                  hint: 'e.g. tcp port 443',
                ),
                onChanged: _capture.setBpfFilter,
              ),
              const SizedBox(height: 12),
              FilterChip(
                label: const Text('Use Tshark'),
                selected: _capture.useTshark,
                onSelected: _isCapturing ? null : _capture.setUseTshark,
                selectedColor: AppColors.cyan.withValues(alpha: 0.15),
                checkmarkColor: AppColors.cyan,
                side: const BorderSide(color: AppColors.borderElevated),
                labelStyle: TextStyle(
                  color: _capture.useTshark ? AppColors.cyanLight : AppColors.textMuted,
                  fontSize: 13,
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Done', style: TextStyle(color: AppColors.cyanLight)),
          ),
        ],
      ),
    );
  }

  List<LivePacket> get _filteredPackets {
    return _capture.packets.where((p) {
      final protocolOk = _selectedProtocol == 'all' ||
          p.protocol.toLowerCase().contains(_selectedProtocol.split('/').first.toLowerCase());
      final riskOk = _riskLevel == 'all' || p.status == _riskLevel;
      return protocolOk && riskOk;
    }).toList();
  }

  LivePacket? get _selectedPacket {
    final data = _filteredPackets;
    if (_selectedPacketIndex == null || data.isEmpty) return null;
    final i = _selectedPacketIndex!;
    if (i < 0 || i >= data.length) return null;
    return data[i];
  }

  Future<void> _toggleCapture() async {
    if (!ApiConfig.isConfigured) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Set your API key in Settings')),
      );
      return;
    }

    try {
      if (!_isCapturing) {
        if (_capture.selectedInterfaceIndex == null) {
          await _showCaptureSettings();
          return;
        }
        await _capture.startCapture();
      } else {
        await _capture.stopCapture();
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))),
      );
    }
  }

  Color _statusColor(String status) {
    switch (status) {
      case 'normal':
        return AppColors.greenLight;
      case 'suspicious':
        return AppColors.orangeLight;
      case 'malicious':
        return AppColors.redLight;
      default:
        return AppColors.textMuted;
    }
  }

  Widget _statusBadge(String status, Color color, {bool uppercase = false}) {
    final label = uppercase ? status.toUpperCase() : status.toLowerCase();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Text(
        label,
        style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600),
      ),
    );
  }

  InputDecoration _fieldDecoration({String? label, String? hint}) {
    return InputDecoration(
      labelText: label,
      hintText: hint,
      labelStyle: const TextStyle(color: AppColors.textDim, fontSize: 13),
      hintStyle: const TextStyle(color: AppColors.textDisabled, fontSize: 13),
      filled: true,
      fillColor: AppColors.border,
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.borderElevated),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: BorderSide(color: AppColors.cyan.withValues(alpha: 0.5)),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
    );
  }

  Widget _styledDropdown<T>({
    required T value,
    required List<DropdownMenuItem<T>> items,
    required ValueChanged<T?> onChanged,
    bool enabled = true,
    double? width,
  }) {
    final dropdown = DropdownButtonHideUnderline(
      child: DropdownButton<T>(
        isExpanded: true,
        value: value,
        dropdownColor: AppColors.panel,
        icon: const Icon(Icons.keyboard_arrow_down, color: AppColors.textMuted, size: 20),
        style: const TextStyle(color: AppColors.textPrimary, fontSize: 14),
        items: items,
        onChanged: enabled ? onChanged : null,
      ),
    );

    return SizedBox(
      width: width,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          color: AppColors.border,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.borderElevated),
        ),
        child: dropdown,
      ),
    );
  }

  Widget _buildControlBar() {
    return CyberCard(
      padding: const EdgeInsets.all(_pagePad),
      child: LayoutBuilder(
        builder: (context, c) {
          final stacked = c.maxWidth < 768;

          final captureBtn = ElevatedButton.icon(
            onPressed: _toggleCapture,
            onLongPress: _showCaptureSettings,
            icon: Icon(_isCapturing ? Icons.pause : Icons.play_arrow, size: 20),
            label: Text(_isCapturing ? 'Stop Capture' : 'Start Capture'),
            style: ElevatedButton.styleFrom(
              backgroundColor: _isCapturing ? AppColors.red : AppColors.cyan,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              textStyle: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
            ),
          );

          final filters = Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.filter_list, color: AppColors.textMuted, size: 20),
              const SizedBox(width: 12),
              _styledDropdown<String>(
                width: 160,
                value: _selectedProtocol,
                items: const [
                  DropdownMenuItem(value: 'all', child: Text('All Protocols')),
                  DropdownMenuItem(value: 'http/https', child: Text('HTTP/HTTPS')),
                  DropdownMenuItem(value: 'ssh', child: Text('SSH')),
                  DropdownMenuItem(value: 'ftp', child: Text('FTP')),
                  DropdownMenuItem(value: 'dns', child: Text('DNS')),
                ],
                onChanged: (v) => setState(() {
                  _selectedProtocol = v ?? 'all';
                  _selectedPacketIndex = _filteredPackets.isEmpty ? null : 0;
                }),
              ),
              const SizedBox(width: 12),
              _styledDropdown<String>(
                width: 168,
                value: _riskLevel,
                items: const [
                  DropdownMenuItem(value: 'all', child: Text('All Risk Levels')),
                  DropdownMenuItem(value: 'normal', child: Text('Normal')),
                  DropdownMenuItem(value: 'suspicious', child: Text('Suspicious')),
                  DropdownMenuItem(value: 'malicious', child: Text('Malicious')),
                ],
                onChanged: (v) => setState(() {
                  _riskLevel = v ?? 'all';
                  _selectedPacketIndex = _filteredPackets.isEmpty ? null : 0;
                }),
              ),
            ],
          );

          if (stacked) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                captureBtn,
                const SizedBox(height: 16),
                filters,
              ],
            );
          }

          return Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              captureBtn,
              const Spacer(),
              Flexible(child: SingleChildScrollView(scrollDirection: Axis.horizontal, child: filters)),
            ],
          );
        },
      ),
    );
  }

  Widget _buildInterfaceSelector({bool compact = true}) {
    if (_capture.isLoadingInterfaces) {
      return const Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.settings_ethernet, color: AppColors.textMuted, size: 20),
          SizedBox(width: 8),
          SizedBox(
            width: 14,
            height: 14,
            child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.cyan),
          ),
          SizedBox(width: 8),
          Text('Loading interfaces...', style: TextStyle(color: AppColors.textMuted, fontSize: 14)),
        ],
      );
    }

    if (_capture.interfaces.isEmpty) {
      return Row(
        mainAxisSize: compact ? MainAxisSize.min : MainAxisSize.max,
        children: [
          const Icon(Icons.settings_ethernet, color: AppColors.textMuted, size: 20),
          const SizedBox(width: 8),
          const Expanded(
            child: Text('No interfaces', style: TextStyle(color: AppColors.textMuted, fontSize: 14)),
          ),
          TextButton(
            onPressed: _capture.loadInterfaces,
            child: const Text('Refresh', style: TextStyle(color: AppColors.cyanLight)),
          ),
        ],
      );
    }

    final selected = _capture.selectedInterfaceIndex;
    if (selected == null) {
      return const Text('Select an interface', style: TextStyle(color: AppColors.textMuted, fontSize: 14));
    }

    return Row(
      children: [
        const Icon(Icons.settings_ethernet, color: AppColors.textMuted, size: 20),
        const SizedBox(width: 8),
        Expanded(
          child: _styledDropdown<int>(
            value: selected,
            enabled: !_isCapturing,
            items: [
              for (final iface in _capture.interfaces)
                DropdownMenuItem(
                  value: iface.index,
                  child: Text(iface.label, overflow: TextOverflow.ellipsis),
                ),
            ],
            onChanged: (v) {
              if (v != null) {
                _capture.selectInterface(v);
                setState(() {});
              }
            },
          ),
        ),
      ],
    );
  }

  Widget _buildStreamPanel() {
    final packets = _filteredPackets;

    return ClipRRect(
      borderRadius: BorderRadius.circular(AppColors.cardRadius),
      child: CyberCard(
        padding: EdgeInsets.zero,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.all(_pagePad),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Text(
                        'Live Packet Stream',
                        style: TextStyle(
                          color: AppColors.textPrimary,
                          fontSize: 18,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (_isCapturing) ...[
                        const SizedBox(width: 10),
                        const PulsingDot(color: AppColors.green, size: 8),
                      ],
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    _streamStatus,
                    style: const TextStyle(color: AppColors.textMuted, fontSize: 14),
                  ),
                ],
              ),
            ),
            const Divider(height: 1, color: AppColors.border),
            Expanded(
              child: packets.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            _isCapturing ? Icons.radar : Icons.wifi_tethering_off,
                            color: AppColors.textDim,
                            size: 40,
                          ),
                          const SizedBox(height: 12),
                          Text(
                            _isCapturing
                                ? 'Waiting for packets...'
                                : 'No packets yet — click Start Capture',
                            style: const TextStyle(color: AppColors.textMuted, fontSize: 14),
                          ),
                        ],
                      ),
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        _PacketTableHeader(),
                        Expanded(
                          child: ListView.builder(
                            itemCount: packets.length,
                            itemBuilder: (context, i) {
                              final packet = packets[i];
                              final selected = i == _selectedPacketIndex;
                              return _PacketTableRow(
                                packet: packet,
                                selected: selected,
                                statusColor: _statusColor(packet.status),
                                onTap: () => setState(() => _selectedPacketIndex = i),
                              );
                            },
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

  Widget _buildDetailsPanel() {
    final packet = _selectedPacket;

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text(
            'Packet Details',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: packet == null
                ? const Center(
                    child: Text(
                      'Select a packet to view details',
                      style: TextStyle(color: AppColors.textDim, fontSize: 14),
                    ),
                  )
                : SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _DetailField(label: 'Source IP', value: packet.ip, mono: true),
                        _DetailField(label: 'Port', value: packet.port),
                        _DetailField(label: 'Protocol', value: packet.protocol),
                        _DetailField(label: 'Packet Size', value: packet.size),
                        const SizedBox(height: 4),
                        const Text(
                          'ML Classification',
                          style: TextStyle(color: AppColors.textDim, fontSize: 12),
                        ),
                        const SizedBox(height: 6),
                        _statusBadge(packet.status, _statusColor(packet.status), uppercase: true),
                        const SizedBox(height: 16),
                        _DetailField(label: 'Timestamp', value: packet.time, mono: true),
                        const SizedBox(height: 16),
                        const Divider(color: AppColors.border),
                        const SizedBox(height: 16),
                        const Text(
                          'Raw Packet Data',
                          style: TextStyle(color: AppColors.textDim, fontSize: 12),
                        ),
                        const SizedBox(height: 8),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: AppColors.border,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: SingleChildScrollView(
                            scrollDirection: Axis.horizontal,
                            child: Text(
                              packet.raw.isNotEmpty
                                  ? packet.raw
                                  : '45 00 00 3c 1c 46 40 00 40 06 b1 e6 ac 10 0a 63...',
                              style: GoogleFonts.jetBrainsMono(
                                color: AppColors.textMuted,
                                fontSize: 12,
                                height: 1.5,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_capture.isLoading && _capture.packets.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(_pagePad),
        child: ShimmerBox(height: 480, width: double.infinity, borderRadius: 10),
      );
    }

    return FadeSlideIn(
      child: Padding(
        padding: const EdgeInsets.all(_pagePad),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildControlBar(),
            const SizedBox(height: _sectionGap),
            Expanded(
              child: MediaQuery.sizeOf(context).width >= 1024
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Expanded(flex: 2, child: _buildStreamPanel()),
                        SizedBox(width: _gridGap),
                        Expanded(child: _buildDetailsPanel()),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Expanded(flex: 3, child: _buildStreamPanel()),
                        SizedBox(height: _gridGap),
                        Expanded(flex: 2, child: _buildDetailsPanel()),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

class _PacketTableHeader extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      color: AppColors.border,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: const Row(
        children: [
          _HeaderCell('IP Address', flex: 3, align: TextAlign.left),
          _HeaderCell('Port', flex: 1, align: TextAlign.left),
          _HeaderCell('Protocol', flex: 2, align: TextAlign.left),
          _HeaderCell('Size', flex: 1, align: TextAlign.right),
          _HeaderCell('Status', flex: 2, align: TextAlign.center),
          _HeaderCell('Time', flex: 2, align: TextAlign.right),
        ],
      ),
    );
  }
}

class _HeaderCell extends StatelessWidget {
  const _HeaderCell(this.label, {required this.flex, required this.align});

  final String label;
  final int flex;
  final TextAlign align;

  @override
  Widget build(BuildContext context) {
    return Expanded(
      flex: flex,
      child: Text(
        label.toUpperCase(),
        textAlign: align,
        style: const TextStyle(
          color: AppColors.textDim,
          fontSize: 11,
          fontWeight: FontWeight.w500,
          letterSpacing: 0.4,
        ),
      ),
    );
  }
}

class _PacketTableRow extends StatelessWidget {
  const _PacketTableRow({
    required this.packet,
    required this.selected,
    required this.statusColor,
    required this.onTap,
  });

  final LivePacket packet;
  final bool selected;
  final Color statusColor;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final bg = selected ? AppColors.rowHover : Colors.transparent;

    return Material(
      color: bg,
      child: InkWell(
        onTap: onTap,
        hoverColor: AppColors.rowHover.withValues(alpha: 0.6),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: AppColors.border)),
          ),
          child: Row(
            children: [
              Expanded(
                flex: 3,
                child: Text(
                  packet.ip,
                  style: GoogleFonts.jetBrainsMono(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                  ),
                ),
              ),
              Expanded(
                flex: 1,
                child: Text(
                  packet.port,
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 13),
                ),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  packet.protocol,
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                ),
              ),
              Expanded(
                flex: 1,
                child: Text(
                  packet.size,
                  textAlign: TextAlign.right,
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 13),
                ),
              ),
              Expanded(
                flex: 2,
                child: Center(child: _StatusBadge(status: packet.status, color: statusColor)),
              ),
              Expanded(
                flex: 2,
                child: Text(
                  packet.time,
                  textAlign: TextAlign.right,
                  style: GoogleFonts.jetBrainsMono(
                    color: AppColors.textMuted,
                    fontSize: 13,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  const _StatusBadge({required this.status, required this.color});

  final String status;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Text(
        status.toLowerCase(),
        style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600),
      ),
    );
  }
}

class _DetailField extends StatelessWidget {
  const _DetailField({
    required this.label,
    required this.value,
    this.mono = false,
  });

  final String label;
  final String value;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(color: AppColors.textDim, fontSize: 12)),
          const SizedBox(height: 4),
          Text(
            value,
            style: mono
                ? GoogleFonts.jetBrainsMono(color: AppColors.textPrimary, fontSize: 14)
                : const TextStyle(color: AppColors.textPrimary, fontSize: 14),
          ),
        ],
      ),
    );
  }
}
