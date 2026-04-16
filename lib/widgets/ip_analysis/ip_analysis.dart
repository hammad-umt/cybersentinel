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
                    child: Container(
                      color: const Color(0xFF1A1F2E),
                      child: const Center(
                        child: Text(
                          'IP Analysis Content Goes Here',
                          style: TextStyle(color: Colors.white, fontSize: 18),
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
