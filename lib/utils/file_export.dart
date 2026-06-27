import 'dart:io';

import 'package:file_picker/file_picker.dart';

/// Saves binary content via the native save dialog, ensuring the file extension.
Future<String?> saveBytesToFile({
  required List<int> bytes,
  required String fileName,
  required String extension,
}) async {
  final path = await FilePicker.platform.saveFile(
    fileName: fileName,
    type: FileType.custom,
    allowedExtensions: [extension],
  );
  if (path == null) return null;

  final lower = path.toLowerCase();
  final ext = extension.toLowerCase();
  final finalPath = lower.endsWith('.$ext') ? path : '$path.$ext';
  await File(finalPath).writeAsBytes(bytes);
  return finalPath;
}
