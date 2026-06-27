import 'package:cybersentinel/services/api_service.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Floating AI copilot — global on all authenticated app screens.
class CopilotAssistantOverlay extends StatefulWidget {
  const CopilotAssistantOverlay({
    super.key,
    required this.isOpen,
    required this.onToggle,
  });

  final bool isOpen;
  final VoidCallback onToggle;

  @override
  State<CopilotAssistantOverlay> createState() => _CopilotAssistantOverlayState();
}

class _CopilotAssistantOverlayState extends State<CopilotAssistantOverlay>
    with SingleTickerProviderStateMixin {
  bool _loading = false;
  final _inputController = TextEditingController();
  final _scrollController = ScrollController();
  final _messages = <_ChatMessage>[];
  late AnimationController _fabPulse;

  static const _quickPrompts = [
    'Hi',
    'Hello',
    'Top threats today?',
    'Summarize firewall alerts',
    'Explain packet capture',
  ];

  @override
  void initState() {
    super.initState();
    _fabPulse = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2200),
    )..repeat(reverse: true);
    _seedWelcome();
  }

  void _seedWelcome() {
    final name = _firstName(AuthService.instance.email);
    _messages.add(
      _ChatMessage(
        text: name.isNotEmpty
            ? 'Hello, $name. I\'m CyberSentinel Copilot — your AI security analyst. '
                'Ask about threats, alerts, captures, or investigation workflows.'
            : 'Hello. I\'m CyberSentinel Copilot — your AI security analyst. '
                'Ask about threats, alerts, captures, or investigation workflows.',
        isUser: false,
        isSystem: true,
      ),
    );
  }

  String _firstName(String email) {
    if (email.isEmpty || !email.contains('@')) return '';
    final local = email.split('@').first;
    if (local.contains('.')) {
      return local.split('.').first;
    }
    return local;
  }

  @override
  void dispose() {
    _fabPulse.dispose();
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _toggle() => widget.onToggle();

  bool get _open => widget.isOpen;

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 280),
        curve: Curves.easeOut,
      );
    });
  }

  bool _isGreeting(String text) {
    final n = text.trim().toLowerCase().replaceAll(RegExp(r'[!?.]+$'), '');
    return const {'hi', 'hello', 'hey', 'hi there', 'hello there', 'good morning', 'good afternoon'}
        .contains(n);
  }

  String _localGreetingReply() {
    final name = _firstName(AuthService.instance.email);
    if (name.isNotEmpty) {
      return 'Hi $name — good to see you. I can help with threat scoring, firewall alerts, '
          'live capture, IP reputation, and report summaries. What would you like to investigate?';
    }
    return 'Hi — good to see you. I can help with threat scoring, firewall alerts, '
        'live capture, IP reputation, and report summaries. What would you like to investigate?';
  }

  String _extractAnswer(Map<String, dynamic> data) {
    for (final key in ['answer', 'response', 'result', 'message', 'detail']) {
      final value = data[key];
      if (value is String && value.trim().isNotEmpty) return value.trim();
    }
    final nested = data['data'];
    if (nested is Map<String, dynamic>) return _extractAnswer(nested);
    return 'I completed the analysis. Check the relevant dashboard section for detailed results, '
        'or ask a more specific question.';
  }

  Future<void> _send([String? preset]) async {
    final text = (preset ?? _inputController.text).trim();
    if (text.isEmpty || _loading) return;

    setState(() {
      _messages.add(_ChatMessage(text: text, isUser: true));
      _loading = true;
      if (preset == null) _inputController.clear();
    });
    if (!_open) widget.onToggle();
    _scrollToBottom();

    try {
      final reply = _isGreeting(text)
          ? _localGreetingReply()
          : _extractAnswer(await ApiService.instance.askCopilot(question: text));

      if (!mounted) return;
      setState(() {
        _messages.add(_ChatMessage(text: reply, isUser: false));
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _messages.add(
          _ChatMessage(
            text: _isGreeting(text)
                ? _localGreetingReply()
                : 'I couldn\'t reach the analysis service right now. '
                    'Please verify the backend is running, then try again.\n\n'
                    'Error: ${e.toString().replaceFirst('Exception: ', '')}',
            isUser: false,
            isError: true,
          ),
        );
        _loading = false;
      });
    }
    _scrollToBottom();
  }

  @override
  Widget build(BuildContext context) {
    final bottomInset = MediaQuery.paddingOf(context).bottom;
    final isWide = MediaQuery.sizeOf(context).width >= 900;
    final fabBottom = isWide ? 24.0 : 76.0 + bottomInset;

    return Stack(
      clipBehavior: Clip.none,
      children: [
        if (_open) ...[
          Positioned.fill(
            child: GestureDetector(
              onTap: _toggle,
              child: Container(color: Colors.black.withValues(alpha: 0.35)),
            ),
          ),
          Positioned(
            top: isWide ? 16 : 0,
            right: isWide ? 16 : 0,
            bottom: isWide ? 16 : 0,
            left: isWide ? null : 0,
            width: isWide ? 400 : null,
            child: _CopilotPanel(
              messages: _messages,
              loading: _loading,
              scrollController: _scrollController,
              inputController: _inputController,
              quickPrompts: _quickPrompts,
              onClose: _toggle,
              onSend: _send,
              onQuickPrompt: (q) => _send(q),
            ),
          ),
        ],
        if (!_open)
          Positioned(
            right: 16,
            bottom: fabBottom,
            child: _CopilotFab(pulse: _fabPulse, onTap: _toggle),
          ),
      ],
    );
  }
}

class _CopilotFab extends StatelessWidget {
  const _CopilotFab({required this.pulse, required this.onTap});

  final AnimationController pulse;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: pulse,
      builder: (context, child) {
        return Container(
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: AppColors.cyan.withValues(alpha: 0.25 + pulse.value * 0.15),
                blurRadius: 16 + pulse.value * 8,
                spreadRadius: pulse.value * 2,
              ),
            ],
          ),
          child: child,
        );
      },
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          customBorder: const CircleBorder(),
          child: Ink(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: const LinearGradient(
                colors: [Color(0xFF0891B2), Color(0xFF06B6D4), Color(0xFF22D3EE)],
              ),
              border: Border.all(color: AppColors.cyanLight.withValues(alpha: 0.4)),
            ),
            child: const Icon(Icons.auto_awesome, color: Colors.white, size: 24),
          ),
        ),
      ),
    );
  }
}

class _CopilotPanel extends StatelessWidget {
  const _CopilotPanel({
    required this.messages,
    required this.loading,
    required this.scrollController,
    required this.inputController,
    required this.quickPrompts,
    required this.onClose,
    required this.onSend,
    required this.onQuickPrompt,
  });

  final List<_ChatMessage> messages;
  final bool loading;
  final ScrollController scrollController;
  final TextEditingController inputController;
  final List<String> quickPrompts;
  final VoidCallback onClose;
  final Future<void> Function([String? preset]) onSend;
  final ValueChanged<String> onQuickPrompt;

  @override
  Widget build(BuildContext context) {
    final isWide = MediaQuery.sizeOf(context).width >= 900;

    return Material(
      elevation: 12,
      shadowColor: Colors.black54,
      borderRadius: BorderRadius.circular(isWide ? 16 : 0),
      color: AppColors.panel,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(isWide ? 16 : 0),
        child: Column(
          children: [
            _PanelHeader(onClose: onClose),
            Expanded(
              child: ListView.builder(
                controller: scrollController,
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                itemCount: messages.length + (loading ? 1 : 0),
                itemBuilder: (context, index) {
                  if (loading && index == messages.length) {
                    return const _TypingIndicator();
                  }
                  return _MessageBubble(message: messages[index]);
                },
              ),
            ),
            if (messages.length <= 3)
              SizedBox(
                height: 36,
                child: ListView.separated(
                  scrollDirection: Axis.horizontal,
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  itemCount: quickPrompts.length,
                  separatorBuilder: (_, __) => const SizedBox(width: 8),
                  itemBuilder: (context, i) {
                    return ActionChip(
                      label: Text(quickPrompts[i]),
                      labelStyle: GoogleFonts.inter(fontSize: 12, color: AppColors.textPrimary),
                      backgroundColor: AppColors.border,
                      side: BorderSide(color: AppColors.borderElevated),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                      onPressed: loading ? null : () => onQuickPrompt(quickPrompts[i]),
                    );
                  },
                ),
              ),
            const SizedBox(height: 8),
            _InputBar(
              controller: inputController,
              loading: loading,
              onSend: () => onSend(),
            ),
          ],
        ),
      ),
    );
  }
}

class _PanelHeader extends StatelessWidget {
  const _PanelHeader({required this.onClose});

  final VoidCallback onClose;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 14, 8, 14),
      decoration: const BoxDecoration(
        border: Border(bottom: BorderSide(color: AppColors.border)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppColors.cyan.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.auto_awesome, color: AppColors.cyanLight, size: 18),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Security Copilot',
                  style: GoogleFonts.inter(
                    color: AppColors.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  'AI-assisted investigation',
                  style: GoogleFonts.inter(color: AppColors.textMuted, fontSize: 11),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: AppColors.green.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(999),
              border: Border.all(color: AppColors.green.withValues(alpha: 0.3)),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 6,
                  height: 6,
                  decoration: const BoxDecoration(color: AppColors.greenLight, shape: BoxShape.circle),
                ),
                const SizedBox(width: 5),
                Text(
                  'Online',
                  style: GoogleFonts.inter(
                    color: AppColors.greenLight,
                    fontSize: 10,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: onClose,
            icon: const Icon(Icons.close_rounded, color: AppColors.textMuted),
            tooltip: 'Close',
          ),
        ],
      ),
    );
  }
}

class _MessageBubble extends StatelessWidget {
  const _MessageBubble({required this.message});

  final _ChatMessage message;

  @override
  Widget build(BuildContext context) {
    final isUser = message.isUser;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        mainAxisAlignment: isUser ? MainAxisAlignment.end : MainAxisAlignment.start,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (!isUser) ...[
            CircleAvatar(
              radius: 14,
              backgroundColor: AppColors.cyan.withValues(alpha: 0.15),
              child: const Icon(Icons.auto_awesome, size: 14, color: AppColors.cyanLight),
            ),
            const SizedBox(width: 8),
          ],
          Flexible(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: isUser
                    ? AppColors.cyan.withValues(alpha: 0.18)
                    : message.isError
                        ? AppColors.red.withValues(alpha: 0.08)
                        : AppColors.border,
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(14),
                  topRight: const Radius.circular(14),
                  bottomLeft: Radius.circular(isUser ? 14 : 4),
                  bottomRight: Radius.circular(isUser ? 4 : 14),
                ),
                border: Border.all(
                  color: isUser
                      ? AppColors.cyan.withValues(alpha: 0.25)
                      : message.isError
                          ? AppColors.red.withValues(alpha: 0.25)
                          : AppColors.borderElevated,
                ),
              ),
              child: Text(
                message.text,
                style: GoogleFonts.inter(
                  color: AppColors.textPrimary,
                  fontSize: 13,
                  height: 1.45,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _TypingIndicator extends StatelessWidget {
  const _TypingIndicator();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12, left: 36),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            decoration: BoxDecoration(
              color: AppColors.border,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: AppColors.borderElevated),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: List.generate(3, (i) {
                return Padding(
                  padding: EdgeInsets.only(left: i == 0 ? 0 : 4),
                  child: _Dot(delay: Duration(milliseconds: i * 180)),
                );
              }),
            ),
          ),
        ],
      ),
    );
  }
}

class _Dot extends StatefulWidget {
  const _Dot({required this.delay});
  final Duration delay;

  @override
  State<_Dot> createState() => _DotState();
}

class _DotState extends State<_Dot> with SingleTickerProviderStateMixin {
  late AnimationController _c;

  @override
  void initState() {
    super.initState();
    _c = AnimationController(vsync: this, duration: const Duration(milliseconds: 600));
    Future.delayed(widget.delay, () {
      if (mounted) _c.repeat(reverse: true);
    });
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FadeTransition(
      opacity: _c,
      child: Container(
        width: 6,
        height: 6,
        decoration: const BoxDecoration(color: AppColors.cyanLight, shape: BoxShape.circle),
      ),
    );
  }
}

class _InputBar extends StatelessWidget {
  const _InputBar({
    required this.controller,
    required this.loading,
    required this.onSend,
  });

  final TextEditingController controller;
  final bool loading;
  final VoidCallback onSend;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: AppColors.border)),
        color: AppColors.chartBg,
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              enabled: !loading,
              style: GoogleFonts.inter(color: AppColors.textPrimary, fontSize: 14),
              cursorColor: AppColors.cyanLight,
              textInputAction: TextInputAction.send,
              onSubmitted: (_) => onSend(),
              decoration: InputDecoration(
                hintText: 'Ask about threats, alerts, or workflows…',
                hintStyle: GoogleFonts.inter(color: AppColors.textDim, fontSize: 13),
                filled: true,
                fillColor: AppColors.border,
                contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none,
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: const BorderSide(color: AppColors.borderElevated),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide(color: AppColors.cyan.withValues(alpha: 0.5)),
                ),
              ),
            ),
          ),
          const SizedBox(width: 8),
          Material(
            color: AppColors.cyan,
            borderRadius: BorderRadius.circular(12),
            child: InkWell(
              onTap: loading ? null : onSend,
              borderRadius: BorderRadius.circular(12),
              child: SizedBox(
                width: 44,
                height: 44,
                child: loading
                    ? const Padding(
                        padding: EdgeInsets.all(12),
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                      )
                    : const Icon(Icons.send_rounded, color: Colors.white, size: 20),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ChatMessage {
  _ChatMessage({
    required this.text,
    required this.isUser,
    this.isSystem = false,
    this.isError = false,
  });

  final String text;
  final bool isUser;
  final bool isSystem;
  final bool isError;
}
