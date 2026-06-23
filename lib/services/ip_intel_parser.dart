/// Parses IP geo + AbuseIPDB fields from backend intel responses.
class IpGeoIntel {
  const IpGeoIntel({
    required this.city,
    required this.countryName,
    required this.countryCode,
    required this.isp,
    required this.asn,
    required this.abuseConfidence,
    required this.totalReports,
    required this.isWhitelisted,
    required this.providerStatus,
    this.latitude,
    this.longitude,
    this.usageType,
  });

  final String city;
  final String countryName;
  final String countryCode;
  final String isp;
  final String asn;
  final int abuseConfidence;
  final int totalReports;
  final bool isWhitelisted;
  final Map<String, String> providerStatus;
  final double? latitude;
  final double? longitude;
  final String? usageType;

  String get locationLabel {
    if (city.isNotEmpty && countryName.isNotEmpty) return '$city, $countryName';
    if (city.isNotEmpty) return city;
    if (countryName.isNotEmpty) return countryName;
    return 'Unknown';
  }

  String get countryLabel =>
      countryCode.isNotEmpty ? countryCode : (countryName.isNotEmpty ? countryName : '--');

  bool get hasCoordinates => latitude != null && longitude != null;

  /// Accepts `/api/v1/firewall/intel/ip/{ip}` or nested intel inside threat score.
  static IpGeoIntel? fromResponse(Map<String, dynamic>? data) {
    if (data == null) return null;

    final reputation = _extractReputation(data);
    if (reputation == null) return null;

    final geo = reputation['raw'] is Map
        ? (reputation['raw'] as Map)['geoip']
        : null;
    final geoMap = geo is Map ? Map<String, dynamic>.from(geo) : null;

    final city = _string(reputation['city'] ?? geoMap?['city']);
    final countryName = _string(
      reputation['country_name'] ?? geoMap?['country'] ?? reputation['country'],
    );
    final countryCode = _string(
      reputation['country_code'] ?? geoMap?['countryCode'],
    ).toUpperCase();
    final isp = _string(
      reputation['isp'] ?? geoMap?['isp'] ?? reputation['as_org'],
    );
    final asn = _string(reputation['asn'] ?? geoMap?['as']);

    final lat = _double(reputation['latitude'] ?? geoMap?['lat']);
    final lon = _double(reputation['longitude'] ?? geoMap?['lon']);

    final providerRaw = reputation['provider_status'];
    final providerStatus = <String, String>{};
    if (providerRaw is Map) {
      for (final entry in providerRaw.entries) {
        providerStatus[entry.key.toString()] = entry.value?.toString() ?? '';
      }
    }

    return IpGeoIntel(
      city: city,
      countryName: countryName,
      countryCode: countryCode,
      isp: isp.isNotEmpty ? isp : 'Unknown ISP',
      asn: asn,
      abuseConfidence: _int(reputation['abuse_confidence_score']),
      totalReports: _int(reputation['total_reports']),
      isWhitelisted: reputation['is_whitelisted'] == true,
      providerStatus: providerStatus,
      latitude: lat,
      longitude: lon,
      usageType: _optionalString(reputation['usage_type']),
    );
  }

  static Map<String, dynamic>? _extractReputation(Map<String, dynamic> data) {
    final direct = data['ip_reputation'];
    if (direct is Map<String, dynamic>) return direct;
    if (direct is Map) return Map<String, dynamic>.from(direct);

    final evidence = data['evidence'];
    if (evidence is Map) {
      final intel = evidence['intel'];
      if (intel is Map) {
        final nested = intel['ip_reputation'];
        if (nested is Map) return Map<String, dynamic>.from(nested);
      }
    }

    // Flat fallback (older shapes)
    if (data.containsKey('isp') ||
        data.containsKey('country_code') ||
        data.containsKey('city')) {
      return data;
    }

    return null;
  }

  static String _string(dynamic value) => value?.toString().trim() ?? '';

  static String? _optionalString(dynamic value) {
    final s = _string(value);
    return s.isEmpty ? null : s;
  }

  static int _int(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }

  static double? _double(dynamic value) {
    if (value is num) return value.toDouble();
    return double.tryParse(value?.toString() ?? '');
  }
}
