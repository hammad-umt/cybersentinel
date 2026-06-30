String? tokenFromResetLinkString(String? raw) {
  if (raw == null || raw.trim().isEmpty) return null;
  final uri = Uri.tryParse(raw.trim());
  if (uri == null) return null;

  final fromQuery = uri.queryParameters['token'];
  if (fromQuery != null && fromQuery.isNotEmpty) return fromQuery;

  // User pasted only the token string (no URL).
  if (!raw.contains('://') && !raw.contains('?') && raw.length >= 20) {
    return raw.trim();
  }
  return null;
}
