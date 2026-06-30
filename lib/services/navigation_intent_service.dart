import 'package:flutter/foundation.dart';

/// Cross-screen navigation intents (global search, alerts, etc.).
class NavigationIntentService extends ChangeNotifier {
  NavigationIntentService._();

  static final instance = NavigationIntentService._();

  int? pendingPageIndex;
  String? pendingIpLookup;
  String? pendingUrlScan;

  void openPage(int index) {
    pendingPageIndex = index;
    notifyListeners();
  }

  void openIpAnalysis(String ip) {
    pendingIpLookup = ip.trim();
    pendingPageIndex = 4;
    notifyListeners();
  }

  void openUrlScan(String url) {
    pendingUrlScan = url.trim();
    pendingPageIndex = 3;
    notifyListeners();
  }

  int? consumePageIndex() {
    final value = pendingPageIndex;
    pendingPageIndex = null;
    return value;
  }

  String? consumeIpLookup() {
    final value = pendingIpLookup;
    pendingIpLookup = null;
    return value;
  }

  String? consumeUrlScan() {
    final value = pendingUrlScan;
    pendingUrlScan = null;
    return value;
  }
}
