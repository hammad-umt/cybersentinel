import 'package:cybersentinel/auth/require_auth.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:cybersentinel/widgets/ip_analysis/ip_analysis_content.dart';
import 'package:flutter/material.dart';

class IPAnalysisContent extends StatelessWidget {
  const IPAnalysisContent({super.key});

  @override
  Widget build(BuildContext context) => const IPAnalysisPageContent();
}

/// Legacy full-page wrapper (no shell — use [MainAppShell] from main.dart).
class IPLogAnalysisPage extends StatelessWidget {
  const IPLogAnalysisPage({super.key});

  @override
  Widget build(BuildContext context) {
    return RequireAuth(
      child: const Scaffold(
        backgroundColor: AppColors.bg,
        body: IPAnalysisContent(),
      ),
    );
  }
}
