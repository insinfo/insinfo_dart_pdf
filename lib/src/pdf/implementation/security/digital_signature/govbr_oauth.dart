import 'dart:convert';
import 'dart:io';

/// Minimal OAuth2 helper for Gov.br CAS endpoints.
class GovBrOAuthClient {
  GovBrOAuthClient({
    Uri? authorizationEndpoint,
    Uri? tokenEndpoint,
    HttpClient? httpClient,
  })  : _authorizationEndpoint = authorizationEndpoint ??
            Uri.parse('https://cas.staging.iti.br/oauth2.0/authorize'),
        _tokenEndpoint =
            tokenEndpoint ?? Uri.parse('https://cas.staging.iti.br/oauth2.0/token'),
        _httpClient = httpClient ?? HttpClient();

  final Uri _authorizationEndpoint;
  final Uri _tokenEndpoint;
  final HttpClient _httpClient;

  /// Builds the authorization URL with the provided query parameters.
  Uri buildAuthorizationUri(Map<String, String> queryParameters) {
    return _authorizationEndpoint.replace(queryParameters: queryParameters);
  }

  /// Exchanges an authorization code for an access token.
  Future<Map<String, dynamic>> exchangeToken({
    required Map<String, String> body,
    Map<String, String>? headers,
  }) async {
    final HttpClientRequest request = await _httpClient.postUrl(_tokenEndpoint);
    request.headers.set(
      HttpHeaders.contentTypeHeader,
      'application/x-www-form-urlencoded',
    );
    headers?.forEach(request.headers.set);
    request.add(utf8.encode(_encodeForm(body)));
    final HttpClientResponse response = await request.close();
    final String responseText = await utf8.decodeStream(response);
    if (response.statusCode != 200) {
      throw HttpException(
        'Gov.br token exchange failed: ${response.statusCode}',
        uri: _tokenEndpoint,
      );
    }
    try {
      final dynamic decoded = jsonDecode(responseText);
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }
    } catch (_) {
      // Fall through.
    }
    return <String, dynamic>{'raw': responseText};
  }

  /// Closes the underlying HTTP client.
  void close({bool force = false}) {
    _httpClient.close(force: force);
  }

  static String _encodeForm(Map<String, String> body) {
    return body.entries
        .map((e) => '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
        .join('&');
  }
}
