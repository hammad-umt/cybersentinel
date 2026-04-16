import 'package:cybersentinel/widgets/sidebar_panel.dart';
import 'package:flutter/material.dart';

class IPLogAnalysisPage extends StatelessWidget {
  const IPLogAnalysisPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            buildSidebarPanel(context, 4),
            Expanded(
              child: Column(
                children: [
                  buildTopNavbar(context, 'IP Analysis'),
                  Expanded(
                    child: SingleChildScrollView(
                      child: Padding(
                        padding: const EdgeInsets.all(20),
                        child: Column(
                          children: [
                            Center(
                              child: Container(
                                width: 1000,
                                height: 100,
                                padding: const EdgeInsets.all(24),
                                decoration: BoxDecoration(
                                  color: const Color(0xFF0F1420),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(
                                    color: const Color(0xFF1A1F2E),
                                    width: 1,
                                  ),
                                  boxShadow: [
                                    BoxShadow(
                                      color: Colors.black.withOpacity(0.3),
                                      blurRadius: 8,
                                      offset: const Offset(0, 4),
                                    ),
                                  ],
                                ),
                                child: Center(
                                  child: Row(
                                    children: [
                                      Expanded(
                                        child: Container(
                                          padding: const EdgeInsets.symmetric(
                                            horizontal: 16,
                                          ),
                                          width: double.infinity,
                                          height: 80,
                                          decoration: BoxDecoration(
                                            color: const Color(0xFF1A1F2E),
                                            borderRadius: BorderRadius.circular(
                                              8,
                                            ),
                                            border: Border.all(
                                              color: const Color(0xFF2A2F3E),
                                              width: 1,
                                            ),
                                          ),
                                          child: TextField(
                                            textAlignVertical:
                                                TextAlignVertical.center,
                                            style: const TextStyle(
                                              color: Color(0xFFD1D5DB),
                                              fontSize: 16,
                                            ),
                                            decoration: InputDecoration(
                                              prefixIcon: const Padding(
                                                padding: EdgeInsets.symmetric(
                                                  horizontal: 12,
                                                ),
                                                child: Icon(
                                                  Icons.search,
                                                  color: Color(0xFF9CA3AF),
                                                  size: 24,
                                                ),
                                              ),
                                              prefixIconConstraints:
                                                  const BoxConstraints(
                                                    minHeight: 40,
                                                  ),
                                              hintText:
                                                  'Enter IP address to analyze (e.g. 192.168.8.1)',
                                              hintStyle: const TextStyle(
                                                color: Color(0xFF6B7280),
                                                fontSize: 16,
                                              ),
                                              border: InputBorder.none,
                                              contentPadding:
                                                  const EdgeInsets.only(
                                                    left: 0,
                                                    right: 16,
                                                    top: 0,
                                                    bottom: 8,
                                                  ),
                                            ),
                                          ),
                                        ),
                                      ),
                                      const SizedBox(width: 16),
                                      ElevatedButton(
                                        onPressed: () {},
                                        style: ElevatedButton.styleFrom(
                                          backgroundColor: const Color(
                                            0xFF06B6D4,
                                          ),
                                          foregroundColor: const Color(
                                            0xFFE5E7EB,
                                          ),
                                          padding: const EdgeInsets.symmetric(
                                            horizontal: 32,
                                            vertical: 20,
                                          ),
                                          shape: RoundedRectangleBorder(
                                            borderRadius: BorderRadius.circular(
                                              8,
                                            ),
                                          ),
                                          elevation: 4,
                                        ),
                                        child: const Text(
                                          'Analyze',
                                          style: TextStyle(
                                            fontSize: 16,
                                            fontWeight: FontWeight.w600,
                                            letterSpacing: 0.5,
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(height: 40),
                            Center(
                              child: Container(
                                width: 1000,
                                height: 400,
                                padding: const EdgeInsets.all(24),
                                decoration: BoxDecoration(
                                  color: const Color(0xFF0F1420),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(
                                    color: const Color(0xFF1A1F2E),
                                    width: 1,
                                  ),
                                  boxShadow: [
                                    BoxShadow(
                                      color: Colors.black.withOpacity(0.3),
                                      blurRadius: 8,
                                      offset: const Offset(0, 4),
                                    ),
                                  ],
                                ),
                                child: Center(
                                  child: Column(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(
                                        Icons.search,
                                        size: 80,
                                        color: Colors.white.withOpacity(0.3),
                                      ),
                                      const SizedBox(height: 24),
                                      Text(
                                        'No IP Analyzed Yet',
                                        style: TextStyle(
                                          color: Colors.white.withOpacity(0.8),
                                          fontSize: 24,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                      const SizedBox(height: 12),
                                      Text(
                                        'Enter an IP address above to view detailed analysis',
                                        style: TextStyle(
                                          color: Colors.white.withOpacity(0.4),
                                          fontSize: 16,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
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
