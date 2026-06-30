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
      title: '',
      subtitle: '',
      heroIcon: Icons.shield_outlined,
      child: AutofillGroup(
        child: Form(
          key: _formKey,
          child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            AuthModeTabs(
              activeIndex: 1,
              onSelect: (i) {
                if (i == 0) Navigator.of(context).pop();
              },
            ),
            const SizedBox(height: 22),
            if (_formError != null) ...[
              AuthFormAlert.error(message: _formError!),
              const SizedBox(height: 20),
            ],
            AuthFormSection(
              label: 'EMAIL',
              child: AuthTextField(
                controller: _emailController,
                focusNode: _emailFocus,
                label: 'Email',
                hint: 'you@example.com',
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
            ),
            const SizedBox(height: 16),
            AuthFormSection(
              label: 'PASSWORD',
              child: AuthTextField(
                controller: _passwordController,
                focusNode: _passwordFocus,
                label: 'Password',
                hint: 'Create a password',
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
            ),
            const SizedBox(height: 16),
            AuthFormSection(
              label: 'CONFIRM PASSWORD',
              child: AuthTextField(
                controller: _confirmController,
                focusNode: _confirmFocus,
                label: 'Confirm password',
                hint: 'Re-enter password',
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
            ),
            const SizedBox(height: 14),
            AuthAuthButton(
              label: 'Sign Up',
              loading: _loading,
              onPressed: _loading ? null : _register,
            ),
          ],
        ),
      ),
    ),
    );
  }
}
