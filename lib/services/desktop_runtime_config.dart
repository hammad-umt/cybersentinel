class DesktopRuntimeConfig {
  DesktopRuntimeConfig._();

  static const int defaultPort = 8000;
  // Chatbot runs on a separate port by default to avoid clashing with the
  // main backend API. Keep this adjacent so desktop clients can discover it.
  static const String host = '127.0.0.1';
  static const String appDataFolderName = 'CyberSentinel';
  static const String runtimeFolderName = 'runtime';
  static const String runtimeConfigFileName = 'desktop_runtime.json';

  static String buildBaseUrl({required int port, String hostValue = host}) {
    return 'http://$hostValue:$port';
  }

  static String buildChatbotUrl({required int port, String hostValue = host}) {
    return buildBaseUrl(port: port, hostValue: hostValue);
  }
}
