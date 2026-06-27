import 'package:cybersentinel/auth/auth_validators.dart';
import 'package:cybersentinel/auth/auth_widgets.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:flutter/material.dart';

class ForgotPasswordScreen extends StatefulWidget {
  const ForgotPasswordScreen({super.key});

  @override
  State<ForgotPasswordScreen> createState() => _ForgotPasswordScreenState();
}

class _ForgotPasswordScreenState extends State<ForgotPasswordScreen> {
  final _emailController = TextEditingController();
  final _emailFocus = FocusNode();

  bool _loading = false;
  bool _sent = false;
  bool _submitted = false;
  String? _emailError;
  String? _formError;

  @override
  void dispose() {
    _emailController.dispose();
    _emailFocus.dispose();
    super.dispose();
  }

  bool _validate() {
    final err = AuthValidators.email(_emailController.text);
    setState(() {
      _emailError = err;
      _formError = null;
    });
    return err == null;
  }

  Future<void> _submit() async {
    setState(() {
      _submitted = true;
      _formError = null;
    });
    if (!_validate()) return;

    setState(() => _loading = true);
    try {
      await AuthService.instance.forgotPassword(email: _emailController.text.trim());
      if (!mounted) return;
      setState(() => _sent = true);
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
      showBack: true,
      backLabel: 'Back to sign in',
      stepLabel: _sent ? 'Check your email' : 'Password recovery · Step 1 of 2',
      title: _sent ? 'Check your inbox' : 'Reset your password',
      subtitle: _sent
          ? 'If an account exists for that address, we sent a secure reset link.'
          : 'We\'ll email you a one-time link to choose a new password.',
      heroIcon: Icons.mail_lock_outlined,
      heroTagline: 'Password recovery with secure, time-limited tokens',
      child: _sent ? _buildSuccessState() : _buildFormState(),
    );
  }

  Widget _buildFormState() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_formError != null) ...[
          AuthFormAlert.error(message: _formError!),
          const SizedBox(height: 20),
        ],
        AuthFormSection(
          label: 'Recovery email',
          child: AuthTextField(
            controller: _emailController,
            focusNode: _emailFocus,
            label: 'Email address',
            hint: 'user@company.com',
            helperText: 'For security, we show the same message whether or not the email exists.',
            errorText: _submitted ? _emailError : null,
            prefixIcon: Icons.alternate_email_rounded,
            keyboardType: TextInputType.emailAddress,
            textInputAction: TextInputAction.done,
            autofillHints: const [AutofillHints.email],
            onChanged: (_) {
              if (_submitted) _validate();
            },
            onSubmitted: (_) => _submit(),
          ),
        ),
        const SizedBox(height: 8),
        AuthCtaBlock(
          primaryLabel: 'Send reset link',
          primaryIcon: Icons.send_rounded,
          primaryLoading: _loading,
          helperText: 'Links expire after a short period for your protection.',
          onPrimary: _loading ? null : _submit,
        ),
      ],
    );
  }

  Widget _buildSuccessState() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        AuthStatusBanner(
          title: 'Email sent',
          icon: Icons.mark_email_read_outlined,
          message:
              'Open the link in your inbox to set a new password. '
              'Didn\'t receive it? Check spam or wait a few minutes, then try again.',
        ),
        const SizedBox(height: 24),
        AuthCtaBlock(
          primaryLabel: 'Return to sign in',
          primaryIcon: Icons.login_rounded,
          onPrimary: () => Navigator.of(context).popUntil((route) => route.isFirst),
        ),
        const SizedBox(height: 12),
        AuthSecondaryButton(
          label: 'Send to a different email',
          icon: Icons.edit_outlined,
          onPressed: () => setState(() {
            _sent = false;
            _submitted = false;
            _emailError = null;
            _formError = null;
          }),
        ),
      ],
    );
  }
}
