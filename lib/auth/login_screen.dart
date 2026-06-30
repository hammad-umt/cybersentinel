import 'package:cybersentinel/auth/auth_navigator.dart';
import 'package:cybersentinel/auth/auth_validators.dart';
import 'package:cybersentinel/auth/auth_widgets.dart';
import 'package:cybersentinel/services/auth_service.dart';
import 'package:flutter/material.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _emailFocus = FocusNode();
  final _passwordFocus = FocusNode();

  bool _loading = false;
  bool _submitted = false;
  String? _emailError;
  String? _passwordError;
  String? _formError;

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    _emailFocus.dispose();
    _passwordFocus.dispose();
    super.dispose();
  }

  bool _validate() {
    final emailErr = AuthValidators.email(_emailController.text);
    final passErr = AuthValidators.password(_passwordController.text);
    setState(() {
      _emailError = emailErr;
      _passwordError = passErr;
      _formError = null;
    });
    return emailErr == null && passErr == null;
  }

  Future<void> _login() async {
    setState(() {
      _submitted = true;
      _formError = null;
    });
    if (!_validate()) return;

    setState(() => _loading = true);
    try {
      await AuthService.instance.login(
        email: _emailController.text.trim(),
        password: _passwordController.text,
      );
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
      title: '',
      subtitle: '',
      heroIcon: Icons.shield_outlined,
      child: AutofillGroup(
        child: Form(
          key: _formKey,
          autovalidateMode: _submitted ? AutovalidateMode.always : AutovalidateMode.disabled,
          child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            AuthModeTabs(
              activeIndex: 0,
              onSelect: (i) {
                if (i == 1) {
                  Navigator.of(context).pushNamed(AuthNavigator.registerRoute);
                }
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
                autofillHints: const [AutofillHints.email, AutofillHints.username],
                onChanged: (_) {
                  if (_submitted) _validate();
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
                hint: '••••••••',
                errorText: _submitted ? _passwordError : null,
                prefixIcon: Icons.lock_outline_rounded,
                obscureText: true,
                textInputAction: TextInputAction.done,
                autofillHints: const [AutofillHints.password],
                onChanged: (_) {
                  if (_submitted) _validate();
                },
                onSubmitted: (_) => _login(),
              ),
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.center,
              child: AuthLinkButton(
                label: 'Forgot password?',
                onPressed: _loading
                    ? () {}
                    : () => Navigator.of(context).pushNamed(AuthNavigator.forgotRoute),
              ),
            ),
            const SizedBox(height: 14),
            AuthAuthButton(
              label: 'Sign In',
              loading: _loading,
              onPressed: _loading ? null : _login,
            ),
          ],
        ),
      ),
    ),
    );
  }
}
