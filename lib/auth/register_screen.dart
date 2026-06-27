import 'package:cybersentinel/auth/auth_validators.dart';
import 'package:cybersentinel/auth/auth_widgets.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:flutter/material.dart';

class RegisterScreen extends StatefulWidget {
  const RegisterScreen({super.key});

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmController = TextEditingController();
  final _emailFocus = FocusNode();
  final _passwordFocus = FocusNode();
  final _confirmFocus = FocusNode();

  bool _loading = false;
  bool _submitted = false;
  String? _emailError;
  String? _passwordError;
  String? _confirmError;
  String? _formError;

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    _confirmController.dispose();
    _emailFocus.dispose();
    _passwordFocus.dispose();
    _confirmFocus.dispose();
    super.dispose();
  }

  bool _validate() {
    final emailErr = AuthValidators.email(_emailController.text);
    final passErr = AuthValidators.password(_passwordController.text);
    final confirmErr = AuthValidators.confirmPassword(
      _confirmController.text,
      _passwordController.text,
    );
    setState(() {
      _emailError = emailErr;
      _passwordError = passErr;
      _confirmError = confirmErr;
      _formError = null;
    });
    return emailErr == null && passErr == null && confirmErr == null;
  }

  Future<void> _register() async {
    setState(() {
      _submitted = true;
      _formError = null;
    });
    if (!_validate()) return;

    setState(() => _loading = true);
    try {
      await AuthService.instance.register(
        email: _emailController.text.trim(),
        password: _passwordController.text,
      );
      if (!mounted) return;
      showAuthSuccess(context, 'Account created successfully.');
      Navigator.of(context).pop();
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
      stepLabel: 'Create account · Step 1 of 1',
      title: 'Create your account',
      subtitle: 'Register to access live capture, threat intel, and SOC dashboards.',
      heroIcon: Icons.person_add_alt_1_rounded,
      heroTagline: 'Analyst-grade tooling for modern security teams',
      child: AutofillGroup(
        child: Form(
          key: _formKey,
          child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_formError != null) ...[
              AuthFormAlert.error(message: _formError!),
              const SizedBox(height: 20),
            ],
            AuthFormSection(
              label: 'Account details',
              child: Column(
                children: [
                  AuthTextField(
                    controller: _emailController,
                    focusNode: _emailFocus,
                    label: 'Work email',
                    hint: 'analyst@company.com',
                    errorText: _submitted ? _emailError : null,
                    prefixIcon: Icons.alternate_email_rounded,
                    keyboardType: TextInputType.emailAddress,
                    textInputAction: TextInputAction.next,
                    autofillHints: const [AutofillHints.email],
                    onChanged: (_) {
                      if (_submitted) _validate();
                      setState(() {});
                    },
                    onSubmitted: (_) => _passwordFocus.requestFocus(),
                  ),
                  const SizedBox(height: 16),
                  AuthTextField(
                    controller: _passwordController,
                    focusNode: _passwordFocus,
                    label: 'Password',
                    hint: 'Create a strong password',
                    errorText: _submitted ? _passwordError : null,
                    prefixIcon: Icons.lock_outline_rounded,
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
                    label: 'Confirm password',
                    hint: 'Re-enter your password',
                    errorText: _submitted ? _confirmError : null,
                    prefixIcon: Icons.verified_user_outlined,
                    obscureText: true,
                    textInputAction: TextInputAction.done,
                    autofillHints: const [AutofillHints.newPassword],
                    onChanged: (_) {
                      if (_submitted) _validate();
                    },
                    onSubmitted: (_) => _register(),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            AuthCtaBlock(
              primaryLabel: 'Create account & continue',
              primaryIcon: Icons.check_rounded,
              primaryLoading: _loading,
              helperText: 'By creating an account you agree to your organization\'s access policy.',
              secondaryPrompt: 'Already have an account?',
              secondaryActionLabel: 'Sign in instead',
              onPrimary: _loading ? null : _register,
              onSecondaryAction: _loading ? null : () => Navigator.of(context).pop(),
            ),
          ],
        ),
      ),
    ),
    );
  }
}
