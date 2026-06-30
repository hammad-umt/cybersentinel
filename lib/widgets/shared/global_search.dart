import 'package:cybersentinel/services/api_config.dart';
import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/services/navigation_intent_service.dart';
import 'package:cybersentinel/services/packet_capture_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class GlobalSearchField extends StatelessWidget {
  const GlobalSearchField({super.key, this.width = 320});

  final double width;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      height: 40,
      child: TextField(
        readOnly: true,
        onTap: () => showGlobalSearch(context),
        style: GoogleFonts.inter(
          color: AppColors.textPrimary,
          fontSize: 14,
          fontWeight: FontWeight.w500,
        ),
        cursorColor: AppColors.cyanLight,
        decoration: InputDecoration(
          hintText: 'Search IPs, pages, alerts…',
          hintStyle: GoogleFonts.inter(
            color: AppColors.textDim,
            fontSize: 14,
            fontWeight: FontWeight.w500,
          ),
          filled: true,
          fillColor: AppColors.border,
          prefixIcon: Icon(Icons.search, color: AppColors.textDim, size: 18),
          suffixIcon: Padding(
            padding: const EdgeInsets.only(right: 10),
            child: Text(
              'Ctrl+K',
              style: GoogleFonts.inter(color: AppColors.textDim, fontSize: 11),
            ),
          ),
          suffixIconConstraints: const BoxConstraints(minWidth: 48),
          contentPadding: const EdgeInsets.symmetric(vertical: 0),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
            borderSide: BorderSide(color: AppColors.borderElevated),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
            borderSide: BorderSide(color: AppColors.cyan.withValues(alpha: 0.5)),
          ),
        ),
      ),
    );
  }
}

Future<void> showGlobalSearch(BuildContext context) async {
  await showDialog<void>(
    context: context,
    barrierColor: Colors.black54,
    builder: (ctx) => const _GlobalSearchDialog(),
  );
}

class _GlobalSearchDialog extends StatefulWidget {
  const _GlobalSearchDialog();

  @override
  State<_GlobalSearchDialog> createState() => _GlobalSearchDialogState();
}

class _GlobalSearchDialogState extends State<_GlobalSearchDialog> {
  final _controller = TextEditingController();
  final _focus = FocusNode();
  List<_SearchResult> _results = [];
  bool _loading = false;

  static const _pages = [
    (0, 'Dashboard', Icons.grid_view_rounded, ['dashboard', 'home', 'overview']),
    (1, 'Packet Tracing', Icons.account_tree_outlined, ['packet', 'capture', 'trace', 'live']),
    (2, 'Firewall Logs', Icons.shield_outlined, ['firewall', 'logs', 'alerts', 'monitor']),
    (3, 'Virus Scanner', Icons.bug_report_outlined, ['virus', 'file', 'url', 'scan', 'vt']),
    (4, 'IP Analysis', Icons.location_on_outlined, ['ip', 'reputation', 'geo', 'threat']),
    (5, 'Reports', Icons.description_outlined, ['report', 'pdf', 'export']),
    (6, 'Settings', Icons.settings_outlined, ['settings', 'profile', 'theme']),
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _focus.requestFocus());
    _controller.addListener(_onQueryChanged);
    _refreshResults('');
  }

  @override
  void dispose() {
    _controller.removeListener(_onQueryChanged);
    _controller.dispose();
    _focus.dispose();
    super.dispose();
  }

  void _onQueryChanged() => _refreshResults(_controller.text.trim());

  Future<void> _refreshResults(String query) async {
    final q = query.toLowerCase();
    final out = <_SearchResult>[];

    for (final page in _pages) {
      if (q.isEmpty ||
          page.$2.toLowerCase().contains(q) ||
          page.$4.any((k) => k.contains(q))) {
        out.add(_SearchResult(
          title: page.$2,
          subtitle: 'Go to ${page.$2}',
          icon: page.$3,
          kind: _SearchKind.page,
          pageIndex: page.$1,
        ));
      }
    }

    if (_looksLikeIp(query)) {
      out.insert(
        0,
        _SearchResult(
          title: 'Analyze IP $query',
          subtitle: 'Threat score & geo intelligence',
          icon: Icons.radar,
          kind: _SearchKind.ip,
          ip: query,
        ),
      );
    }

    if (_looksLikeUrl(query)) {
      out.insert(
        0,
        _SearchResult(
          title: 'Scan URL',
          subtitle: query,
          icon: Icons.link,
          kind: _SearchKind.url,
          url: query.startsWith('http') ? query : 'https://$query',
        ),
      );
    }

    for (final packet in PacketCaptureService.instance.packets) {
      if (q.isNotEmpty && !packet.ip.toLowerCase().contains(q)) continue;
      if (q.isEmpty && out.length > 12) break;
      out.add(_SearchResult(
        title: packet.ip,
        subtitle: '${packet.protocol} :${packet.port} — ${packet.status}',
        icon: Icons.lan_outlined,
        kind: _SearchKind.ip,
        ip: packet.ip,
      ));
    }

    if (ApiConfig.isConfigured && q.length >= 2) {
      setState(() => _loading = true);
      try {
        final data = await ApiService.instance.getFirewallAlerts(pageSize: 8);
        for (final raw in data['alerts'] as List? ?? []) {
          if (raw is! Map) continue;
          final map = Map<String, dynamic>.from(raw);
          final ip = map['src_ip']?.toString() ?? '';
          final rule = map['rule']?.toString() ?? map['severity']?.toString() ?? '';
          if (q.isNotEmpty &&
              !ip.toLowerCase().contains(q) &&
              !rule.toLowerCase().contains(q)) {
            continue;
          }
          out.add(_SearchResult(
            title: ip.isEmpty ? 'Firewall alert' : ip,
            subtitle: rule,
            icon: Icons.shield,
            kind: _SearchKind.ip,
            ip: ip.isEmpty ? null : ip,
            pageIndex: 2,
          ));
        }
      } catch (_) {
        // Offline search still works for pages/packets.
      }
    }

    if (!mounted) return;
    setState(() {
      _results = out.take(12).toList();
      _loading = false;
    });
  }

  bool _looksLikeIp(String value) {
    final parts = value.split('.');
    if (parts.length != 4) return false;
    return parts.every((p) {
      final n = int.tryParse(p);
      return n != null && n >= 0 && n <= 255;
    });
  }

  bool _looksLikeUrl(String value) {
    final v = value.toLowerCase();
    return v.contains('.') && (v.startsWith('http') || v.contains('www.') || !v.contains(' '));
  }

  void _select(_SearchResult result) {
    final nav = NavigationIntentService.instance;
    switch (result.kind) {
      case _SearchKind.page:
        nav.openPage(result.pageIndex!);
      case _SearchKind.ip:
        if (result.ip != null && result.ip!.isNotEmpty) {
          nav.openIpAnalysis(result.ip!);
        } else if (result.pageIndex != null) {
          nav.openPage(result.pageIndex!);
        }
      case _SearchKind.url:
        if (result.url != null) nav.openUrlScan(result.url!);
    }
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560),
        child: Material(
          color: AppColors.panel,
          elevation: 12,
          borderRadius: BorderRadius.circular(14),
          child: Container(
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: AppColors.cyan.withValues(alpha: 0.25)),
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                  child: TextField(
                    controller: _controller,
                    focusNode: _focus,
                    style: GoogleFonts.inter(color: AppColors.textPrimary, fontSize: 15),
                    decoration: InputDecoration(
                      hintText: 'Search IPs, URLs, pages…',
                      hintStyle: GoogleFonts.inter(color: AppColors.textDim),
                      prefixIcon: Icon(Icons.search, color: AppColors.cyanLight),
                      suffixIcon: _loading
                          ? const Padding(
                              padding: EdgeInsets.all(12),
                              child: SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              ),
                            )
                          : IconButton(
                              icon: Icon(Icons.close, color: AppColors.textMuted, size: 20),
                              onPressed: () => Navigator.pop(context),
                            ),
                      filled: true,
                      fillColor: AppColors.border,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                        borderSide: BorderSide.none,
                      ),
                    ),
                    onSubmitted: (v) {
                      if (_results.isNotEmpty) _select(_results.first);
                    },
                  ),
                ),
                const Divider(height: 1),
                if (_results.isEmpty)
                  Padding(
                    padding: const EdgeInsets.all(28),
                    child: Text(
                      'Type an IP, URL, or page name…',
                      style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 13),
                    ),
                  )
                else
                  Flexible(
                    child: ListView.builder(
                      shrinkWrap: true,
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      itemCount: _results.length,
                      itemBuilder: (context, i) {
                        final r = _results[i];
                        return ListTile(
                          leading: Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: AppColors.cyan.withValues(alpha: 0.12),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Icon(r.icon, color: AppColors.cyanLight, size: 18),
                          ),
                          title: Text(
                            r.title,
                            style: GoogleFonts.inter(
                              color: AppColors.textPrimary,
                              fontWeight: FontWeight.w600,
                              fontSize: 14,
                            ),
                          ),
                          subtitle: Text(
                            r.subtitle,
                            style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 12),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          onTap: () => _select(r),
                        );
                      },
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

enum _SearchKind { page, ip, url }

class _SearchResult {
  const _SearchResult({
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.kind,
    this.pageIndex,
    this.ip,
    this.url,
  });

  final String title;
  final String subtitle;
  final IconData icon;
  final _SearchKind kind;
  final int? pageIndex;
  final String? ip;
  final String? url;
}
