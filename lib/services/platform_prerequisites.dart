import 'platform_prerequisites_io.dart'
    if (dart.library.html) 'platform_prerequisites_web.dart' as impl;

/// Desktop packet-capture prerequisites (Npcap on Windows, libpcap on Linux).
/// On web, this is a no-op — the browser talks to a remote API only.
class PlatformPrerequisites {
  PlatformPrerequisites._();

  static Future<void> ensureReady() => impl.ensureReady();

  static String get bootTitle => impl.bootTitle;

  static String get bootSubtitle => impl.bootSubtitle;
}
