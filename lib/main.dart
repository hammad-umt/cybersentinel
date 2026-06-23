import 'package:cybersentinel/app_shell.dart';
import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/packet_capture_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await ApiConfig.load();
  await PacketCaptureService.instance.initialize();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: AppColors.bg,
        colorScheme: ColorScheme.fromSeed(seedColor: AppColors.border),
        textTheme: GoogleFonts.interTextTheme(),
        textSelectionTheme: const TextSelectionThemeData(
          selectionColor: Colors.white,
          cursorColor: AppColors.cyanLight,
        ),
      ),
      home: const MainAppShell(),
    );
  }
}
