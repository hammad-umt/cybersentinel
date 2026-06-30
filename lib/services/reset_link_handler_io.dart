import 'dart:io';

import 'reset_link_tokens.dart';

String? get initialToken {
  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    for (final arg in Platform.executableArguments) {
      final token = tokenFromResetLinkString(arg);
      if (token != null && token.isNotEmpty) return token;
    }
  }
  return tokenFromResetLinkString(Uri.base.toString());
}
