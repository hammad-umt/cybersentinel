import 'package:cybersentinel/auth/auth_navigator.dart';
import 'package:cybersentinel/auth/auth_validators.dart';
import 'package:cybersentinel/auth/auth_widgets.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:cybersentinel/services/reset_link_handler.dart';
import 'package:cybersentinel/theme/app_colors.dart';
import 'package:flutter/material.dart';

class ResetPasswordScreen extends StatefulWidget {
  const ResetPasswordScreen({super.key, this.token = ''});

  final String token;

  @override
  State<ResetPasswordScreen> createState() => _ResetPasswordScreenState();
}

class _ResetPasswordScreenState extends State<ResetPasswordScreen> {
  final _passwordController = TextEditingController();
  final _confirmController = TextEditingController();
  final _passwordFocus = FocusNode();
  final _confirmFocus = FocusNode();

  bool _loading = false;
  bool _validating = true;
  bool _tokenValid = false;
  bool _done = false;
  bool _submitted = false;
  String? _passwordError;
  String? _confirmError;
  String? _validationError;
  String? _formError;
  late String _activeToken;
  final _tokenController = TextEditingController();
  final _tokenFocus = FocusNode();

  @override
  void initState() {
    super.initState();
    _activeToken = widget.token.trim();
    if (_activeToken.isNotEmpty) {
      _validateToken();
    } else {
      _validating = false;
    }
  }

  @override
  void dispose() {
    _tokenController.dispose();
    _tokenFocus.dispose();
    _passwordController.dispose();
    _confirmController.dispose();
    _passwordFocus.dispose();
    _confirmFocus.dispose();
    super.dispose();
  }

  Future<void> _validateToken() async {
    if (_activeToken.isEmpty) return;
    setState(() {
      _validating = true;
      _validationError = null;
    });
    try {
      await AuthService.instance.validateResetToken(_activeToken);
      if (mounted) {
        setState(() {
          _tokenValid = true;
          _validating = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _tokenValid = false;
          _validating = false;
          _validationError = e.toString().replaceFirst('Exception: ', '');
        });
      }
    }
  }

  bool _validate() {
    final passErr = AuthValidators.password(_passwordController.text);
    final confirmErr = AuthValidators.confirmPassword(
      _confirmController.text,
      _passwordController.text,
    );
    setState(() {
      _passwordError = passErr;
      _confirmError = confirmErr;
      _formError = null;
    });
    return passErr == null && confirmErr == null;
  }

  Future<void> _reset() async {
    setState(() {
      _submitted = true;
      _formError = null;
    });
    if (!_validate()) return;

    setState(() => _loading = true);
    try {
      await AuthService.instance.resetPassword(
        token: _activeToken,
        newPassword: _passwordController.text,
      );
      if (!mounted) return;
      setState(() => _done = true);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _formError = e.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return AuthScaffold(
      showBack: !_validating && !_done && _tokenValid,
      backLabel: 'Back to sign in',
      stepLabel: _done
          ? 'Complete'
          : _validating
              ? 'Verifying link'
              : null,
      title: _done
          ? 'Password updated'
          : _validating
              ? 'Verifying reset link'
              : _tokenValid
                  ? 'Choose a new password'
                  : 'Link expired',
      subtitle: _done
          ? 'Your credentials have been updated. Sign in with your new password.'
          : _validating
              ? 'Please wait while we confirm your reset link is still valid.'
              : _tokenValid
                  ? 'Create a strong password you can remember.'
                  : 'This reset link is invalid or has already been used.',
      heroIcon: Icons.key_rounded,
      heroTagline: 'Recover access to your account',
      child: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_activeToken.isEmpty) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const AuthStatusBanner(
            title: 'Open from email or paste token',
            icon: Icons.mail_outline_rounded,
            message:
                'Click the reset link in your email to open CyberSentinel automatically. '
                'If that does not work, copy the reset link or token from the email and paste it below.',
            color: AppColors.cyan,
          ),
          const SizedBox(height: 20),
          AuthTextField(
            controller: _tokenController,
            focusNode: _tokenFocus,
            label: 'Reset link or token',
            hint: 'Paste from email',
            prefixIcon: Icons.link_rounded,
            textInputAction: TextInputAction.done,
            onSubmitted: (_) => _applyPastedToken(),
          ),
          const SizedBox(height: 16),
          AuthCtaBlock(
            primaryLabel: 'Continue',
            primaryIcon: Icons.arrow_forward_rounded,
            onPrimary: _applyPastedToken,
          ),
        ],
      );
    }

    if (_validating) {
      return const AuthLoadingState(message: 'Validating secure reset token…');
    }

    if (_done) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const AuthStatusBanner(
            title: 'You\'re all set',
            icon: Icons.check_circle_outline,
            message:
                'Your password was changed successfully. '
                'Use your new password the next time you sign in.',
            color: AppColors.greenLight,
          ),
          const SizedBox(height: 24),
          AuthCtaBlock(
            primaryLabel: 'Continue to sign in',
            primaryIcon: Icons.login_rounded,
            onPrimary: () => Navigator.of(context).popUntil((route) => route.isFirst),
          ),
        ],
      );
    }

    if (!_tokenValid) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          AuthStatusBanner(
            title: 'Unable to reset',
            icon: Icons.link_off_rounded,
            message: _validationError ?? 'Request a new link from the forgot password screen.',
            color: AppColors.redLight,
          ),
          const SizedBox(height: 20),
          AuthCtaBlock(
            primaryLabel: 'Request new reset link',
            primaryIcon: Icons.mail_outline_rounded,
            onPrimary: () {
              Navigator.of(context).popUntil((route) => route.isFirst);
              Navigator.of(context).pushNamed(AuthNavigator.forgotRoute);
            },
          ),
          const SizedBox(height: 12),
          AuthSecondaryButton(
            label: 'Back to sign in',
            onPressed: () => Navigator.of(context).popUntil((route) => route.isFirst),
          ),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_formError != null) ...[
          AuthFormAlert.error(message: _formError!),
          const SizedBox(height: 20),
        ],
        AuthFormSection(
          label: 'New credentials',
          child: Column(
            children: [
              AuthTextField(
                controller: _passwordController,
                focusNode: _passwordFocus,
                label: 'New password',
                hint: 'Minimum 8 characters',
                errorText: _submitted ? _passwordError : null,
                prefixIcon: Icons.lock_reset_rounded,
                obscureText: true,
                textInputAction: TextInputAction.next,
                autofillHints: const [AutofillHints.newPassword],
                onChanged: (_) {
                  if (_submitted) _validate();
                  setState(() {});
                },
                onSubmitted: (_) => _confirmFocus.requestFocus(),
              ),
              if (_passwordController.text.isNotEmpty) ...[
                const SizedBox(height: 10),
                AuthPasswordStrength(password: _passwordController.text),
              ],
              const SizedBox(height: 16),
              AuthTextField(
                controller: _confirmController,
                focusNode: _confirmFocus,
                label: 'Confirm new password',
                hint: 'Re-enter your new password',
                errorText: _submitted ? _confirmError : null,
                prefixIcon: Icons.verified_user_outlined,
                obscureText: true,
                textInputAction: TextInputAction.done,
                autofillHints: const [AutofillHints.newPassword],
                onChanged: (_) {
                  if (_submitted) _validate();
                },
                onSubmitted: (_) => _reset(),
              ),
            ],
          ),
        ),
        const SizedBox(height: 8),
        AuthCtaBlock(
          primaryLabel: 'Save new password',
          primaryIcon: Icons.save_rounded,
          primaryLoading: _loading,
          helperText: 'You will need to sign in again after updating your password.',
          onPrimary: _loading ? null : _reset,
        ),
      ],
    );
  }

  void _applyPastedToken() {
    final parsed = ResetLinkHandler.tokenFromString(_tokenController.text);
    if (parsed == null || parsed.isEmpty) {
      setState(() {
        _validationError = 'Paste the full reset link or token from your email.';
        _tokenValid = false;
      });
      return;
    }
    setState(() {
      _activeToken = parsed;
      _validating = true;
      _tokenValid = false;
      _validationError = null;
    });
    _validateToken();
  }
}
