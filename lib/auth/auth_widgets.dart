import 'dart:ui';

import 'package:cybersentinel/auth/auth_validators.dart';
import 'package:cybersentinel/theme/auth_colors.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

// ─── Layout ─────────────────────────────────────────────────────────────────

class AuthScaffold extends StatelessWidget {
  const AuthScaffold({
    super.key,
    required this.title,
    required this.subtitle,
    required this.child,
    this.showBack = false,
    this.backLabel = 'Back',
    this.heroIcon = Icons.shield_outlined,
    this.heroTagline = 'Secure access to your SOC dashboard',
    this.stepLabel,
  });

  final String title;
  final String subtitle;
  final Widget child;
  final bool showBack;
  final String backLabel;
  final IconData heroIcon;
  final String heroTagline;
  final String? stepLabel;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        fit: StackFit.expand,
        children: [
          const _AuthBackground(),
          SafeArea(child: _buildSingleColumn(context)),
        ],
      ),
    );
  }

  Widget _buildSingleColumn(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: Column(
            children: [
              const SizedBox(height: 10),
              const _AuthLoginHeader(),
              const SizedBox(height: 22),
              _AuthFormCard(
                title: title,
                subtitle: subtitle,
                showBack: showBack,
                backLabel: backLabel,
                stepLabel: stepLabel,
                child: child,
              ),
              const SizedBox(height: 14),
            ],
          ),
        ),
      ),
    );
  }
}

class _AuthBackground extends StatelessWidget {
  const _AuthBackground();

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: AuthColors.bg,
      ),
      child: Stack(
        fit: StackFit.expand,
        children: [
          // Subtle, non-gimmicky lighting so the screen feels “designed”, not “generated”.
          Positioned(
            top: -180,
            right: -120,
            child: _GlowOrb(color: AuthColors.cyan.withValues(alpha: 0.10), size: 420),
          ),
          Positioned(
            bottom: -220,
            left: -160,
            child: _GlowOrb(color: AuthColors.violet.withValues(alpha: 0.08), size: 520),
          ),
          CustomPaint(painter: _SoftGridPainter()),
        ],
      ),
    );
  }
}

class _SoftGridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = AuthColors.borderElevated.withValues(alpha: 0.22)
      ..strokeWidth = 1;

    const spacing = 56.0;
    for (var x = 0.0; x < size.width; x += spacing) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), paint);
    }
    for (var y = 0.0; y < size.height; y += spacing) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), paint);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class _GlowOrb extends StatelessWidget {
  const _GlowOrb({required this.color, required this.size});
  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: RadialGradient(colors: [color, color.withValues(alpha: 0)]),
      ),
    );
  }
}

class _AuthLoginHeader extends StatelessWidget {
  const _AuthLoginHeader();

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Icon(Icons.shield_outlined, color: AuthColors.greenLight, size: 26),
        const SizedBox(height: 10),
        Text(
          'CYBER  SENTINEL',
          style: GoogleFonts.jetBrainsMono(
            color: AuthColors.cyanLight,
            fontSize: 28,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.0,
          ),
        ),
        const SizedBox(height: 6),
        Text(
          'SECURITY  INTELLIGENCE  PLATFORM',
          style: GoogleFonts.jetBrainsMono(
            color: AuthColors.textDim,
            fontSize: 12,
            fontWeight: FontWeight.w600,
            letterSpacing: 2.6,
          ),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }
}

class AuthModeTabs extends StatelessWidget {
  const AuthModeTabs({
    super.key,
    required this.activeIndex,
    required this.onSelect,
  });

  final int activeIndex; // 0 = sign in, 1 = sign up
  final ValueChanged<int> onSelect;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        color: AuthColors.inputBg.withValues(alpha: 0.7),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AuthColors.borderElevated),
      ),
      child: Row(
        children: [
          Expanded(
            child: _AuthTabButton(
              selected: activeIndex == 0,
              label: 'Sign In',
              icon: Icons.login_rounded,
              onTap: () => onSelect(0),
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: _AuthTabButton(
              selected: activeIndex == 1,
              label: 'Sign Up',
              icon: Icons.person_add_alt_1_rounded,
              onTap: () => onSelect(1),
            ),
          ),
        ],
      ),
    );
  }
}

class _AuthTabButton extends StatelessWidget {
  const _AuthTabButton({
    required this.selected,
    required this.label,
    required this.icon,
    required this.onTap,
  });

  final bool selected;
  final String label;
  final IconData icon;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final fg = selected ? Colors.black : AuthColors.textMuted;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: selected ? AuthColors.greenLight : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 16, color: fg),
              const SizedBox(width: 8),
              Text(
                label,
                style: GoogleFonts.inter(
                  color: fg,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AuthFormCard extends StatelessWidget {
  const _AuthFormCard({
    required this.title,
    required this.subtitle,
    required this.child,
    required this.showBack,
    required this.backLabel,
    this.stepLabel,
  });

  final String title;
  final String subtitle;
  final Widget child;
  final bool showBack;
  final String backLabel;
  final String? stepLabel;

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(20),
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
        child: Container(
          width: double.infinity,
          decoration: BoxDecoration(
            color: AuthColors.panel.withValues(alpha: 0.92),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: AuthColors.borderElevated.withValues(alpha: 0.9)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.35),
                blurRadius: 24,
                offset: const Offset(0, 14),
              ),
            ],
          ),
          padding: const EdgeInsets.fromLTRB(28, 20, 28, 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (showBack) ...[
                AuthBackButton(label: backLabel),
                const SizedBox(height: 8),
              ],
              child,
            ],
          ),
        ),
      ),
    );
  }
}

// ─── Navigation & trust ─────────────────────────────────────────────────────

class AuthBackButton extends StatelessWidget {
  const AuthBackButton({super.key, required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.centerLeft,
      child: TextButton.icon(
        onPressed: () => Navigator.of(context).maybePop(),
        icon: Icon(Icons.arrow_back_rounded, size: 18),
        label: Text(label),
        style: TextButton.styleFrom(
          foregroundColor: AuthColors.textMuted,
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
          minimumSize: const Size(48, 44),
          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        ),
      ),
    );
  }
}

class AuthTrustFooter extends StatelessWidget {
  const AuthTrustFooter({super.key});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.lock_outline, size: 14, color: AuthColors.textDim.withValues(alpha: 0.9)),
        const SizedBox(width: 6),
        Text(
          'Encrypted connection · Session-based access',
          style: GoogleFonts.inter(color: AuthColors.textDim, fontSize: 11),
        ),
      ],
    );
  }
}

// ─── Form chrome ────────────────────────────────────────────────────────────

class AuthFormAlert extends StatelessWidget {
  const AuthFormAlert.error({super.key, required this.message})
      : _isError = true,
        title = null;

  const AuthFormAlert.success({super.key, required this.title, required this.message})
      : _isError = false;

  final bool _isError;
  final String? title;
  final String message;

  @override
  Widget build(BuildContext context) {
    final isError = _isError;
    final color = isError ? AuthColors.redLight : AuthColors.greenLight;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.28)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(isError ? Icons.error_outline : Icons.check_circle_outline, color: color, size: 22),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (title != null) ...[
                  Text(
                    title!,
                    style: GoogleFonts.inter(
                      color: AuthColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                ],
                Text(
                  message,
                  style: GoogleFonts.inter(color: AuthColors.textMuted, fontSize: 13, height: 1.45),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class AuthFormSection extends StatelessWidget {
  const AuthFormSection({super.key, required this.label, required this.child});

  final String label;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.jetBrainsMono(
            color: AuthColors.textMuted,
            fontSize: 12,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.2,
          ),
        ),
        const SizedBox(height: 12),
        child,
      ],
    );
  }
}

class AuthAuthButton extends StatelessWidget {
  const AuthAuthButton({
    super.key,
    required this.label,
    required this.loading,
    required this.onPressed,
  });

  final String label;
  final bool loading;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: ElevatedButton(
        onPressed: loading ? null : onPressed,
        style: ElevatedButton.styleFrom(
          backgroundColor: AuthColors.greenLight,
          foregroundColor: Colors.black,
          disabledBackgroundColor: AuthColors.borderElevated,
          disabledForegroundColor: AuthColors.textDim,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          elevation: 0,
          textStyle: GoogleFonts.jetBrainsMono(fontSize: 16, fontWeight: FontWeight.w700, letterSpacing: 0.8),
        ),
        child: loading
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
              )
            : Text(label.toUpperCase()),
      ),
    );
  }
}

class AuthCtaBlock extends StatelessWidget {
  const AuthCtaBlock({
    super.key,
    required this.primaryLabel,
    required this.onPrimary,
    this.primaryLoading = false,
    this.primaryIcon,
    this.primaryEnabled = true,
    this.helperText,
    this.secondaryPrompt,
    this.secondaryActionLabel,
    this.onSecondaryAction,
  });

  final String primaryLabel;
  final VoidCallback? onPrimary;
  final bool primaryLoading;
  final IconData? primaryIcon;
  final bool primaryEnabled;
  final String? helperText;
  final String? secondaryPrompt;
  final String? secondaryActionLabel;
  final VoidCallback? onSecondaryAction;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        AuthPrimaryButton(
          label: primaryLabel,
          icon: primaryIcon,
          loading: primaryLoading,
          enabled: primaryEnabled,
          onPressed: onPrimary,
        ),
        if (helperText != null) ...[
          const SizedBox(height: 10),
          Text(
            helperText!,
            textAlign: TextAlign.center,
            style: GoogleFonts.inter(color: AuthColors.textDim, fontSize: 12, height: 1.4),
          ),
        ],
        if (secondaryPrompt != null && secondaryActionLabel != null) ...[
          const SizedBox(height: 20),
          const AuthDivider(),
          const SizedBox(height: 12),
          AuthFormFooter(
            prompt: secondaryPrompt!,
            actionLabel: secondaryActionLabel!,
            onAction: onSecondaryAction,
          ),
        ],
      ],
    );
  }
}

class AuthFormFooter extends StatelessWidget {
  const AuthFormFooter({
    super.key,
    required this.prompt,
    required this.actionLabel,
    this.onAction,
  });

  final String prompt;
  final String actionLabel;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Text(prompt, style: GoogleFonts.inter(color: AuthColors.textMuted, fontSize: 14)),
        AuthLinkButton(label: actionLabel, onPressed: onAction ?? () {}),
      ],
    );
  }
}

// ─── Inputs ─────────────────────────────────────────────────────────────────

class AuthTextField extends StatefulWidget {
  const AuthTextField({
    super.key,
    required this.controller,
    required this.label,
    this.hint,
    this.helperText,
    this.errorText,
    this.obscureText = false,
    this.keyboardType,
    this.textInputAction,
    this.autofillHints,
    this.prefixIcon,
    this.focusNode,
    this.onSubmitted,
    this.onChanged,
    this.required = true,
    this.textCapitalization = TextCapitalization.none,
  });

  final TextEditingController controller;
  final String label;
  final String? hint;
  final String? helperText;
  final String? errorText;
  final bool obscureText;
  final TextInputType? keyboardType;
  final TextInputAction? textInputAction;
  final Iterable<String>? autofillHints;
  final IconData? prefixIcon;
  final FocusNode? focusNode;
  final ValueChanged<String>? onSubmitted;
  final ValueChanged<String>? onChanged;
  final bool required;
  final TextCapitalization textCapitalization;

  @override
  State<AuthTextField> createState() => _AuthTextFieldState();
}

class _AuthTextFieldState extends State<AuthTextField> {
  bool _focused = false;
  bool _obscured = true;

  @override
  Widget build(BuildContext context) {
    final hasError = widget.errorText != null && widget.errorText!.isNotEmpty;
    final borderColor = hasError
        ? AuthColors.redLight
        : _focused
            ? AuthColors.cyan
            : AuthColors.borderElevated.withValues(alpha: 0.85);

    return Semantics(
      label: widget.label,
      textField: true,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          AnimatedContainer(
            duration: const Duration(milliseconds: 180),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(12),
              boxShadow: _focused && !hasError
                  ? [BoxShadow(color: Colors.black.withValues(alpha: 0.22), blurRadius: 14)]
                  : [],
            ),
            child: Focus(
              onFocusChange: (v) => setState(() => _focused = v),
              child: TextField(
                controller: widget.controller,
                focusNode: widget.focusNode,
                obscureText: widget.obscureText && _obscured,
                keyboardType: widget.keyboardType,
                textInputAction: widget.textInputAction,
                textCapitalization: widget.textCapitalization,
                autofillHints: widget.autofillHints,
                onSubmitted: widget.onSubmitted,
                onChanged: widget.onChanged,
                style: GoogleFonts.jetBrainsMono(color: AuthColors.textPrimary, fontSize: 15),
                cursorColor: AuthColors.cyanLight,
                decoration: InputDecoration(
                  filled: true,
                  fillColor: AuthColors.inputBg,
                  hintText: widget.hint,
                  hintStyle: GoogleFonts.jetBrainsMono(color: AuthColors.textDim, fontSize: 14),
                  errorText: null,
                  prefixIcon: widget.prefixIcon != null
                      ? Icon(widget.prefixIcon, color: hasError ? AuthColors.redLight : AuthColors.textDim, size: 20)
                      : null,
                  suffixIcon: widget.obscureText
                      ? IconButton(
                          tooltip: _obscured ? 'Show password' : 'Hide password',
                          onPressed: () => setState(() => _obscured = !_obscured),
                          icon: Icon(
                            _obscured ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                            color: AuthColors.textMuted,
                            size: 20,
                          ),
                        )
                      : null,
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(color: borderColor, width: hasError ? 1.5 : 1),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(color: borderColor, width: 1.5),
                  ),
                  contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 16),
                ),
              ),
            ),
          ),
          if (hasError) ...[
            const SizedBox(height: 6),
            Row(
              children: [
                Icon(Icons.info_outline, size: 14, color: AuthColors.redLight),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    widget.errorText!,
                    style: GoogleFonts.inter(color: AuthColors.redLight, fontSize: 12, height: 1.3),
                  ),
                ),
              ],
            ),
          ] else if (widget.helperText != null) ...[
            const SizedBox(height: 6),
            Text(
              widget.helperText!,
              style: GoogleFonts.inter(color: AuthColors.textDim, fontSize: 12, height: 1.35),
            ),
          ],
        ],
      ),
    );
  }
}

class AuthPasswordStrength extends StatelessWidget {
  const AuthPasswordStrength({super.key, required this.password});

  final String password;

  @override
  Widget build(BuildContext context) {
    if (password.isEmpty) return const SizedBox.shrink();

    final score = AuthValidators.passwordStrength(password);
    final label = AuthValidators.passwordStrengthLabel(score);
    final color = switch (score) {
      1 => AuthColors.redLight,
      2 => AuthColors.orangeLight,
      3 => AuthColors.yellowLight,
      4 => AuthColors.greenLight,
      _ => AuthColors.textDim,
    };

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            for (var i = 0; i < 4; i++)
              Expanded(
                child: Container(
                  height: 4,
                  margin: EdgeInsets.only(right: i < 3 ? 6 : 0),
                  decoration: BoxDecoration(
                    color: i < score ? color : AuthColors.borderElevated,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
            if (label.isNotEmpty) ...[
              const SizedBox(width: 10),
              Text(label, style: GoogleFonts.inter(color: color, fontSize: 11, fontWeight: FontWeight.w600)),
            ],
          ],
        ),
        const SizedBox(height: 8),
        AuthPasswordChecklist(password: password),
      ],
    );
  }
}

class AuthPasswordChecklist extends StatelessWidget {
  const AuthPasswordChecklist({super.key, required this.password});

  final String password;

  @override
  Widget build(BuildContext context) {
    final rules = [
      (_Rule('At least 8 characters', password.length >= 8)),
      (_Rule('Upper & lower case', RegExp(r'[A-Z]').hasMatch(password) && RegExp(r'[a-z]').hasMatch(password))),
      (_Rule('Number or symbol', RegExp(r'[0-9]').hasMatch(password) || RegExp(r'[^A-Za-z0-9]').hasMatch(password))),
    ];

    return Column(
      children: [
        for (final rule in rules)
          Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Row(
              children: [
                Icon(
                  rule.met ? Icons.check_circle : Icons.radio_button_unchecked,
                  size: 14,
                  color: rule.met ? AuthColors.greenLight : AuthColors.textDim,
                ),
                const SizedBox(width: 8),
                Text(
                  rule.label,
                  style: GoogleFonts.inter(
                    color: rule.met ? AuthColors.textMuted : AuthColors.textDim,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
      ],
    );
  }
}

class _Rule {
  const _Rule(this.label, this.met);
  final String label;
  final bool met;
}

// ─── Buttons ────────────────────────────────────────────────────────────────

class AuthPrimaryButton extends StatelessWidget {
  const AuthPrimaryButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.loading = false,
    this.enabled = true,
    this.icon,
  });

  final String label;
  final VoidCallback? onPressed;
  final bool loading;
  final bool enabled;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final active = enabled && !loading && onPressed != null;

    return Semantics(
      button: true,
      enabled: active,
      label: label,
      child: SizedBox(
        width: double.infinity,
        height: 52,
        child: DecoratedBox(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            gradient: active
                ? const LinearGradient(
                    colors: [Color(0xFF0891B2), Color(0xFF06B6D4), Color(0xFF22D3EE)],
                  )
                : null,
            color: active ? null : AuthColors.borderElevated.withValues(alpha: 0.6),
            boxShadow: active
                ? [BoxShadow(color: AuthColors.cyan.withValues(alpha: 0.28), blurRadius: 18, offset: const Offset(0, 6))]
                : [],
          ),
          child: Material(
            color: Colors.transparent,
            child: InkWell(
              onTap: active ? onPressed : null,
              borderRadius: BorderRadius.circular(12),
              child: Center(
                child: loading
                    ? const SizedBox(
                        width: 22,
                        height: 22,
                        child: CircularProgressIndicator(strokeWidth: 2.2, color: Colors.white),
                      )
                    : Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            label,
                            style: GoogleFonts.inter(
                              color: active ? Colors.white : AuthColors.textDim,
                              fontSize: 15,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.15,
                            ),
                          ),
                          if (icon != null) ...[
                            const SizedBox(width: 8),
                            Icon(icon, color: active ? Colors.white : AuthColors.textDim, size: 18),
                          ],
                        ],
                      ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class AuthSecondaryButton extends StatelessWidget {
  const AuthSecondaryButton({super.key, required this.label, required this.onPressed, this.icon});

  final String label;
  final VoidCallback onPressed;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      height: 48,
      child: OutlinedButton.icon(
        onPressed: onPressed,
        icon: Icon(icon ?? Icons.arrow_back_rounded, size: 18),
        label: Text(label),
        style: OutlinedButton.styleFrom(
          foregroundColor: AuthColors.textPrimary,
          side: BorderSide(color: AuthColors.borderElevated.withValues(alpha: 0.9)),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          backgroundColor: AuthColors.border.withValues(alpha: 0.3),
          textStyle: GoogleFonts.inter(fontWeight: FontWeight.w600, fontSize: 14),
        ),
      ),
    );
  }
}

class AuthLinkButton extends StatelessWidget {
  const AuthLinkButton({super.key, required this.label, required this.onPressed});

  final String label;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return TextButton(
      onPressed: onPressed,
      style: TextButton.styleFrom(
        foregroundColor: AuthColors.cyanLight,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        minimumSize: const Size(44, 44),
      ),
      child: Text(
        label,
        style: GoogleFonts.inter(color: AuthColors.cyanLight, fontSize: 14, fontWeight: FontWeight.w600),
      ),
    );
  }
}

class AuthDivider extends StatelessWidget {
  const AuthDivider({super.key});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(child: Divider(color: AuthColors.borderElevated.withValues(alpha: 0.7))),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Text('or', style: GoogleFonts.inter(color: AuthColors.textDim, fontSize: 12)),
        ),
        Expanded(child: Divider(color: AuthColors.borderElevated.withValues(alpha: 0.7))),
      ],
    );
  }
}

class AuthStatusBanner extends StatelessWidget {
  const AuthStatusBanner({
    super.key,
    required this.title,
    required this.message,
    required this.icon,
    this.color = AuthColors.cyanLight,
  });

  final String title;
  final String message;
  final IconData icon;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.22)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(icon, color: color, size: 22),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  title,
                  style: GoogleFonts.inter(
                    color: AuthColors.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            message,
            style: GoogleFonts.inter(color: AuthColors.textMuted, fontSize: 13, height: 1.5),
          ),
        ],
      ),
    );
  }
}

class AuthLoadingState extends StatelessWidget {
  const AuthLoadingState({super.key, required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const SizedBox(height: 12),
        CircularProgressIndicator(color: AuthColors.cyan, strokeWidth: 2.5),
        const SizedBox(height: 20),
        Text(
          message,
          textAlign: TextAlign.center,
          style: GoogleFonts.inter(color: AuthColors.textMuted, fontSize: 14),
        ),
      ],
    );
  }
}

// ─── Feedback ───────────────────────────────────────────────────────────────

void showAuthError(BuildContext context, Object error) {
  final message = error.toString().replaceFirst('Exception: ', '');
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(
      SnackBar(
        behavior: SnackBarBehavior.floating,
        margin: const EdgeInsets.all(16),
        backgroundColor: const Color(0xFF7F1D1D),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        content: Row(
          children: [
            Icon(Icons.error_outline, color: Colors.white, size: 18),
            const SizedBox(width: 10),
            Expanded(child: Text(message)),
          ],
        ),
      ),
    );
}

void showAuthSuccess(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(
      SnackBar(
        behavior: SnackBarBehavior.floating,
        margin: const EdgeInsets.all(16),
        backgroundColor: const Color(0xFF065F46),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        content: Row(
          children: [
            Icon(Icons.check_circle_outline, color: Colors.white, size: 18),
            const SizedBox(width: 10),
            Expanded(child: Text(message)),
          ],
        ),
      ),
    );
}
