import 'reset_link_handler_io.dart'
    if (dart.library.html) 'reset_link_handler_web.dart' as impl;
import 'reset_link_tokens.dart';

/// Reads password-reset tokens from email deep links (desktop) or web URLs.
class ResetLinkHandler {
  ResetLinkHandler._();

  /// `cybersentinel://reset-password?token=...` (desktop installer)
  /// or `https://your-site/reset-password?token=...` (Flutter web).
  static const desktopResetBase = 'cybersentinel://reset-password';

  /// Token from app launch arguments or current page URL (web).
  static String? get initialToken => impl.initialToken;

  static String? tokenFromString(String? raw) => tokenFromResetLinkString(raw);
}
