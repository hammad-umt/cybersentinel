import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';

const List<Map<String, String>> packetData = [
  {
    'ip': '192.168.1.45',
    'port': '443',
    'protocol': 'HTTPS',
    'size': '1.2 KB',
    'status': 'normal',
    'time': '14:23:45',
  },
  {
    'ip': '10.0.0.234',
    'port': '22',
    'protocol': 'SSH',
    'size': '512 B',
    'status': 'suspicious',
    'time': '14:23:46',
  },
  {
    'ip': '172.16.0.88',
    'port': '80',
    'protocol': 'HTTP',
    'size': '2.4 KB',
    'status': 'malicious',
    'time': '14:23:47',
  },
  {
    'ip': '192.168.0.156',
    'port': '8080',
    'protocol': 'HTTP',
    'size': '3.1 KB',
    'status': 'normal',
    'time': '14:23:48',
  },
  {
    'ip': '10.1.1.23',
    'port': '3306',
    'protocol': 'MySQL',
    'size': '768 B',
    'status': 'suspicious',
    'time': '14:23:49',
  },
];

class PacketTracingPage extends StatelessWidget {
  const PacketTracingPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildSidebarPanel(context, 1),
            Expanded(
              child: Column(
                children: [
                  buildTopNavbar(context, 'Packet Tracing'),
                  Expanded(
                    child: Container(
                      color: const Color(0xFF0B1120),
                      child: const PacketTracingScreen(),
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

class PacketTracingScreen extends StatefulWidget {
  const PacketTracingScreen({super.key});

  @override
  State<PacketTracingScreen> createState() => _PacketTracingScreenState();
}

class _PacketTracingScreenState extends State<PacketTracingScreen> {
  String _selectedProtocol = 'all';
  String _riskLevel = 'all';
  IconData icon = Icons.play_arrow_outlined;
  String tableDescription = 'Paused';
  Color btnColor = Colors.cyan;
  String btnText = 'Start Capture';
  int _selectedPacketIndex = 0;

  Color getStatusColor(String status) {
    switch (status) {
      case 'normal':
        return const Color.fromARGB(255, 0, 152, 5);
      case 'suspicious':
        return const Color.fromARGB(255, 193, 125, 0);
      case 'malicious':
        return const Color.fromARGB(255, 252, 0, 0);
      default:
        return Colors.white;
    }
  }

  Map<String, String> get _selectedPacket {
    if (packetData.isEmpty) {
      return const {
        'ip': '-',
        'port': '-',
        'protocol': '-',
        'size': '-',
        'status': 'normal',
        'time': '-',
      };
    }

    if (_selectedPacketIndex < 0 || _selectedPacketIndex >= packetData.length) {
      return packetData.first;
    }

    return packetData[_selectedPacketIndex];
  }

  String _getPacketClassification(String status) {
    switch (status) {
      case 'normal':
        return 'NORMAL';
      case 'suspicious':
        return 'SUSPICIOUS';
      case 'malicious':
        return 'MALICIOUS';
      default:
        return status.toUpperCase();
    }
  }

  List<TableRow> _buildDataRows() {
    final List<TableRow> rows = [];

    for (int i = 0; i < packetData.length; i++) {
      final packet = packetData[i];
      final isSelected = i == _selectedPacketIndex;

      rows.add(
        TableRow(
          children: [
            _buildRowCell(
              rowIndex: i,
              isSelected: isSelected,
              child: Text(
                packet['ip']!,
                style: TextStyle(
                  color: isSelected ? Colors.white : const Color(0xFFB8C4DD),
                  fontSize: 13,
                ),
              ),
            ),
            _buildRowCell(
              rowIndex: i,
              isSelected: isSelected,
              child: Text(
                packet['port']!,
                style: TextStyle(
                  color: isSelected ? Colors.white : const Color(0xFFB8C4DD),
                  fontSize: 13,
                ),
              ),
            ),
            _buildRowCell(
              rowIndex: i,
              isSelected: isSelected,
              child: Text(
                packet['protocol']!,
                style: TextStyle(
                  color: isSelected ? Colors.white : const Color(0xFFB8C4DD),
                  fontSize: 13,
                ),
              ),
            ),
            _buildRowCell(
              rowIndex: i,
              isSelected: isSelected,
              child: Text(
                packet['size']!,
                style: TextStyle(
                  color: isSelected ? Colors.white : const Color(0xFFB8C4DD),
                  fontSize: 13,
                ),
              ),
            ),
            _buildRowCell(
              rowIndex: i,
              isSelected: isSelected,
              child: Container(
                alignment: Alignment.center,
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 5,
                ),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(10),
                  color: getStatusColor(packet['status']!).withOpacity(0.07),
                  border: Border.all(
                    color: getStatusColor(packet['status']!),
                    width: 0.5,
                  ),
                ),
                child: Text(
                  packet['status']!,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: getStatusColor(packet['status']!),
                    fontSize: 12,
                  ),
                ),
              ),
            ),
            _buildRowCell(
              rowIndex: i,
              isSelected: isSelected,
              child: Text(
                packet['time']!,
                style: TextStyle(
                  color: isSelected ? Colors.white : const Color(0xFFB8C4DD),
                  fontSize: 15,
                ),
              ),
            ),
          ],
        ),
      );
    }

    return rows;
  }

  Widget _buildRowCell({
    required int rowIndex,
    required bool isSelected,
    required Widget child,
  }) {
    return GestureDetector(
      onTap: () {
        setState(() {
          _selectedPacketIndex = rowIndex;
        });
      },
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 8.0),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF121A2C) : Colors.transparent,
          border: Border(
            bottom: BorderSide(
              color: Colors.white.withOpacity(0.08),
              width: 0.6,
            ),
          ),
        ),
        child: Center(child: child),
      ),
    );
  }

  Widget _buildDetailItem(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 20.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: const TextStyle(color: Color(0xFF7F8AA8), fontSize: 13),
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPacketDetailsPanel() {
    final packet = _selectedPacket;
    final statusColor = getStatusColor(packet['status']!);

    return Padding(
      padding: const EdgeInsets.only(top: 18.0, right: 18.0, bottom: 18.0),
      child: Container(
        decoration: BoxDecoration(
          color: const Color(0xFF0B1120),
          borderRadius: BorderRadius.circular(14.0),
          border: Border.all(color: const Color(0xFF20283A)),
        ),
        padding: const EdgeInsets.fromLTRB(28, 24, 28, 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'Packet Details',
              style: TextStyle(
                color: Colors.white,
                fontSize: 20,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 18),
            _buildDetailItem('Source IP', packet['ip']!),
            _buildDetailItem('Port', packet['port']!),
            _buildDetailItem('Protocol', packet['protocol']!),
            _buildDetailItem('Packet Size', packet['size']!),
            const Text(
              'ML Classification',
              style: TextStyle(color: Color(0xFF7F8AA8), fontSize: 13),
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: statusColor.withOpacity(0.7)),
                color: statusColor.withOpacity(0.12),
              ),
              child: Text(
                _getPacketClassification(packet['status']!),
                style: TextStyle(color: statusColor, fontSize: 13),
              ),
            ),
            const SizedBox(height: 18),
            _buildDetailItem('Timestamp', packet['time']!),
            const Divider(color: Color(0xFF20283A), height: 24),
            const Text(
              'Raw Packet Data',
              style: TextStyle(color: Color(0xFF7F8AA8), fontSize: 13),
            ),
            const SizedBox(height: 10),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0xFF0B1120),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                '45 00 00 3c 1c 46 40 00 40 06 b1 e6 ac 10 0a 63...',
                style: TextStyle(
                  color: Colors.white.withOpacity(0.75),
                  fontFamily: 'monospace',
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 18, 18, 0),
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF0B1120),
                  borderRadius: BorderRadius.circular(8.0),
                  border: Border.all(color: const Color(0xFF20283A)),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: TextButton(
                          style: TextButton.styleFrom(
                            backgroundColor: btnColor,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 20.0,
                              vertical: 12.0,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10.0),
                            ),
                          ),
                          onPressed: () {
                            setState(() {
                              btnColor = btnColor == Colors.cyan
                                  ? Colors.red
                                  : Colors.cyan;
                              icon = icon == Icons.play_arrow_outlined
                                  ? Icons.pause
                                  : Icons.play_arrow_outlined;
                              tableDescription = tableDescription == 'Paused'
                                  ? 'Capturing packets...'
                                  : 'Paused';
                              btnText = btnText == 'Start Capture'
                                  ? 'Stop Capture'
                                  : 'Start Capture';
                            });
                          },
                          child: Padding(
                            padding: const EdgeInsets.all(4.0),
                            child: Row(
                              children: [
                                Icon(icon, color: Colors.white, size: 35),
                                const SizedBox(width: 8.0),
                                Text(
                                  btnText,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 15,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),
                      Row(
                        children: [
                          const Icon(
                            Icons.filter_alt_outlined,
                            color: Colors.white,
                          ),
                          const SizedBox(width: 20.0),
                          DropdownButton<String>(
                            value: _selectedProtocol,
                            dropdownColor: const Color(0xFF0B1120),
                            underline: Container(height: 1, color: Colors.cyan),
                            items: const [
                              DropdownMenuItem(
                                value: 'all',
                                child: Text(
                                  'All Protocols',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'http/https',
                                child: Text(
                                  'HTTP/HTTPS',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'ssh',
                                child: Text(
                                  'SSH',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'ftp',
                                child: Text(
                                  'FTP',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'dns',
                                child: Text(
                                  'DNS',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                            ],
                            onChanged: (value) {
                              setState(() {
                                _selectedProtocol = value!;
                              });
                            },
                          ),
                          const SizedBox(width: 20.0),
                          DropdownButton<String>(
                            value: _riskLevel,
                            dropdownColor: const Color(0xFF0B1120),
                            underline: Container(height: 1, color: Colors.cyan),
                            items: const [
                              DropdownMenuItem(
                                value: 'all',
                                child: Text(
                                  'All Risk Levels',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'normal',
                                child: Text(
                                  'Normal',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'suspicious',
                                child: Text(
                                  'Suspicious',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              DropdownMenuItem(
                                value: 'malicious',
                                child: Text(
                                  'Malicious',
                                  style: TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                            ],
                            onChanged: (String? value) {
                              setState(() {
                                _riskLevel = value!;
                              });
                            },
                          ),
                          const SizedBox(width: 16.0),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  flex: 2,
                  child: Padding(
                    padding: const EdgeInsets.all(18.0),
                    child: Container(
                      decoration: BoxDecoration(
                        color: const Color(0xFF0B1120),
                        borderRadius: BorderRadius.circular(14.0),
                        border: Border.all(color: const Color(0xFF20283A)),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Padding(
                            padding: const EdgeInsets.fromLTRB(20, 14, 0, 10),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Live Packet Stream',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 20,
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                                Text(
                                  tableDescription,
                                  style: const TextStyle(
                                    color: Color(0xFFB8C4DD),
                                    fontSize: 15,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Padding(
                            padding: const EdgeInsets.all(8.0),
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Container(
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF121A2C),
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  child: Table(
                                    children: [
                                      TableRow(
                                        children: [
                                          Center(
                                            child: Padding(
                                              padding:
                                                  const EdgeInsets.symmetric(
                                                    vertical: 8.0,
                                                  ),
                                              child: Text(
                                                'IP Address',
                                                textAlign: TextAlign.center,
                                                style: TextStyle(
                                                  color: Colors.white
                                                      .withOpacity(0.82),
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ),
                                          ),
                                          Center(
                                            child: Padding(
                                              padding:
                                                  const EdgeInsets.symmetric(
                                                    vertical: 8.0,
                                                  ),
                                              child: Text(
                                                'Port',
                                                textAlign: TextAlign.center,
                                                style: TextStyle(
                                                  color: Colors.white
                                                      .withOpacity(0.82),
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ),
                                          ),
                                          Center(
                                            child: Padding(
                                              padding:
                                                  const EdgeInsets.symmetric(
                                                    vertical: 8.0,
                                                  ),
                                              child: Text(
                                                'Protocol',
                                                textAlign: TextAlign.center,
                                                style: TextStyle(
                                                  color: Colors.white
                                                      .withOpacity(0.82),
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ),
                                          ),
                                          Center(
                                            child: Padding(
                                              padding:
                                                  const EdgeInsets.symmetric(
                                                    vertical: 8.0,
                                                  ),
                                              child: Text(
                                                'Size',
                                                textAlign: TextAlign.center,
                                                style: TextStyle(
                                                  color: Colors.white
                                                      .withOpacity(0.82),
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ),
                                          ),
                                          Center(
                                            child: Padding(
                                              padding:
                                                  const EdgeInsets.symmetric(
                                                    vertical: 8.0,
                                                  ),
                                              child: Text(
                                                'Status',
                                                textAlign: TextAlign.center,
                                                style: TextStyle(
                                                  color: Colors.white
                                                      .withOpacity(0.82),
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ),
                                          ),
                                          Center(
                                            child: Padding(
                                              padding:
                                                  const EdgeInsets.symmetric(
                                                    vertical: 8.0,
                                                  ),
                                              child: Text(
                                                'Timestamp',
                                                textAlign: TextAlign.center,
                                                style: TextStyle(
                                                  color: Colors.white
                                                      .withOpacity(0.82),
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ),
                                          ),
                                        ],
                                      ),
                                    ],
                                  ),
                                ),
                                const SizedBox(height: 4),
                                Table(children: [..._buildDataRows()]),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Expanded(child: _buildPacketDetailsPanel()),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
