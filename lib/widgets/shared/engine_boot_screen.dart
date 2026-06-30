import 'dart:async';

import 'package:cybersentinel/services/backend_launcher.dart';
import 'package:cybersentinel/services/platform_prerequisites.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Shown while the local FastAPI engine is starting (Windows / Linux desktop).
class EngineBootScreen extends StatefulWidget {
  const EngineBootScreen({super.key, required this.child});

  final Widget child;

  @override
  State<EngineBootScreen> createState() => _EngineBootScreenState();
}

class _EngineBootScreenState extends State<EngineBootScreen> {
  Future<void>? _boot;

  @override
  void initState() {
    super.initState();
    _boot = _startPlatform();
  }

  Future<void> _startPlatform() async {
    await BackendLauncher.instance.start();
    if (!kIsWeb) {
      // Npcap is only needed for live capture — do not block login on it.
      unawaited(PlatformPrerequisites.ensureReady());
    }
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<void>(
      future: _boot,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return Scaffold(
            backgroundColor: AppColors.bg,
            body: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const CircularProgressIndicator(color: AppColors.cyan),
                  const SizedBox(height: 24),
                  Text(
                    PlatformPrerequisites.bootTitle,
                    style: GoogleFonts.inter(
                      color: AppColors.textPrimary,
                      fontSize: 16,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    PlatformPrerequisites.bootSubtitle,
                    style: GoogleFonts.inter(
                      color: AppColors.textMuted,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
          );
        }

        if (snapshot.hasError) {
          return Scaffold(
            backgroundColor: AppColors.bg,
            body: Padding(
              padding: const EdgeInsets.all(32),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 560),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.error_outline, color: AppColors.red, size: 48),
                      const SizedBox(height: 16),
                      Text(
                        kIsWeb
                            ? 'Cannot reach backend'
                            : 'Backend engine failed to start',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.inter(
                          color: AppColors.textPrimary,
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 12),
                      Text(
                        '${snapshot.error}',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.inter(
                          color: AppColors.textMuted,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 24),
                      FilledButton(
                        onPressed: () {
                          setState(() {
                            _boot = _startPlatform();
                          });
                        },
                        child: const Text('Retry'),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          );
        }

        return widget.child;
      },
    );
  }
}
