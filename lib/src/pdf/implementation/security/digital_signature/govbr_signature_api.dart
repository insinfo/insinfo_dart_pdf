import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Minimal client for the Gov.br signature API (server-side usage).
class GovBrSignatureApi {
  GovBrSignatureApi({
    Uri? baseUri,
    HttpClient? httpClient,
  })  : _baseUri = baseUri ??
            Uri.parse('https://assinatura-api.staging.iti.br/externo/v2/'),
        _httpClient = httpClient ?? HttpClient();

  final Uri _baseUri;
  final HttpClient _httpClient;

  /// Fetches the user's public certificate in PEM format.
  Future<String> getPublicCertificatePem(String accessToken) async {
    final Uri uri = _baseUri.resolve('certificadoPublico');
    final HttpClientRequest request = await _httpClient.getUrl(uri);
    request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $accessToken');
    final HttpClientResponse response = await request.close();
    final Uint8List bytes = await _readAllBytes(response);
    if (response.statusCode != 200) {
      throw HttpException(
        'Gov.br certificadoPublico failed: ${response.statusCode}',
        uri: uri,
      );
    }
    return utf8.decode(bytes);
  }

  /// Signs a Base64 SHA-256 hash and returns PKCS#7 (DER) bytes.
  Future<Uint8List> signHashPkcs7({
    required String accessToken,
    required String hashBase64,
  }) async {
    final Uri uri = _baseUri.resolve('assinarPKCS7');
    final HttpClientRequest request = await _httpClient.postUrl(uri);
    request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $accessToken');
    request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    request.add(utf8.encode(jsonEncode(<String, String>{
      'hashBase64': hashBase64,
    })));
    final HttpClientResponse response = await request.close();
    final Uint8List bytes = await _readAllBytes(response);
    if (response.statusCode != 200) {
      throw HttpException(
        'Gov.br assinarPKCS7 failed: ${response.statusCode}',
        uri: uri,
      );
    }
    return bytes;
  }

  /// Closes the underlying HTTP client.
  void close({bool force = false}) {
    _httpClient.close(force: force);
  }

  static Future<Uint8List> _readAllBytes(HttpClientResponse response) async {
    final BytesBuilder builder = BytesBuilder();
    await for (final List<int> chunk in response) {
      builder.add(chunk);
    }
    return builder.takeBytes();
  }
}
