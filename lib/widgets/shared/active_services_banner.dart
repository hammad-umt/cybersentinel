import 'package:cybersentinel/services/firewall_monitor_service.dart';
import 'package:cybersentinel/services/packet_capture_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Persistent bar shown on every screen while capture or firewall monitor runs.
class ActiveServicesBanner extends StatelessWidget {
  const ActiveServicesBanner({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: Listenable.merge([
        PacketCaptureService.instance,
        FirewallMonitorService.instance,
      ]),
      builder: (context, _) {
        final capture = PacketCaptureService.instance;
        final monitor = FirewallMonitorService.instance;
        final chips = <Widget>[];

        if (capture.isCapturing) {
          chips.add(
            _ServiceChip(
              icon: Icons.radar,
              label: 'Packet capture',
              detail: capture.activeInterfaceName ?? capture.selectedInterface?.name ?? 'active',
              color: AppColors.cyan,
              onStop: () async {
                try {
                  await capture.stopCapture();
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text(e.toString())),
                    );
                  }
                }
              },
            ),
          );
        }

        if (monitor.isMonitoring) {
          chips.add(
            _ServiceChip(
              icon: Icons.shield,
              label: 'Firewall monitor',
              detail: 'live',
              color: AppColors.orange,
              onStop: () async {
                try {
                  await monitor.stopMonitor();
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text(e.toString())),
                    );
                  }
                }
              },
            ),
          );
        }

        if (chips.isEmpty) return const SizedBox.shrink();

        return Material(
          color: AppColors.panel,
          elevation: 2,
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: BoxDecoration(
              border: Border(
                bottom: BorderSide(color: AppColors.cyan.withValues(alpha: 0.25)),
              ),
            ),
            child: Wrap(
              spacing: 10,
              runSpacing: 8,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Icon(Icons.sensors, color: AppColors.cyanLight, size: 18),
                Text(
                  'Active services',
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                ...chips,
              ],
            ),
          ),
        );
      },
    );
  }
}

class _ServiceChip extends StatelessWidget {
  const _ServiceChip({
    required this.icon,
    required this.label,
    required this.detail,
    required this.color,
    required this.onStop,
  });

  final IconData icon;
  final String label;
  final String detail;
  final Color color;
  final Future<void> Function() onStop;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 6),
          Text(
            '$label · $detail',
            style: GoogleFonts.inter(
              color: AppColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(width: 8),
          InkWell(
            onTap: onStop,
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              child: Text(
                'Stop',
                style: GoogleFonts.inter(
                  color: AppColors.redLight,
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
