import 'dart:convert';
import 'package:http/http.dart' as http;
import '../../../io/stream_reader.dart';
import '../asn1/asn1.dart';
import '../asn1/asn1_stream.dart';
import '../asn1/der.dart';

/// Class responsible for handling Time Stamp Protocol (RFC 3161) operations.
/// It generates TimeStampRequest and validates TimeStampResponse.
class TimeStampClient {
  /// Creates a new TimeStampClient with the TSA URL.
  TimeStampClient(this.tsaUrl, {this.username, this.password});

  /// The URL of the Time Stamp Authority.
  final String tsaUrl;

  /// Optional username for basic authentication.
  final String? username;

  /// Optional password for basic authentication.
  final String? password;

  /// Generates a time stamp token for the given message digest.
  ///
  /// [messageDigest] is the hash of the content to be timestamped.
  /// [hashAlgorithm] is the OID of the hash algorithm used (default SHA-256).
  Future<List<int>> getTimeStampToken(
    List<int> messageDigest, {
    String hashAlgorithm = '2.16.840.1.101.3.4.2.1', // SHA-256
    bool requestCert = true,
    BigInt? nonce,
  }) async {
    // 1. Generate Nonce if not provided
    nonce ??= _generateNonce();

    // 2. Create TimeStampRequest (RFC 3161)
    final List<int> requestBytes = _createTimeStampRequest(
      messageDigest,
      hashAlgorithm,
      nonce,
      requestCert,
    );

    // 3. Send Request to TSA
    final http.Response response = await _sendRequest(requestBytes);

    if (response.statusCode != 200) {
      throw ArgumentError(
          'TSA server returned error status: ${response.statusCode}\nBody: ${response.body}');
    }

    // 4. Parse Response
    final List<int> responseBytes = response.bodyBytes;
    return _extractTokenFromResponse(responseBytes);
  }

  /// Generates a random nonce.
  BigInt _generateNonce() {
    final int now = DateTime.now().millisecondsSinceEpoch;
    return BigInt.from(now); // Simple nonce for now, improve with SecureRandom
  }

  /// Creates specific ASN.1 structure for TimeStampRequest
  /// TimeStampRequest ::= SEQUENCE {
  ///   version                      INTEGER { v1(1) },
  ///   messageImprint               MessageImprint,
  ///   reqPolicy             [0]    TSAPolicyId              OPTIONAL,
  ///   nonce                 [1]    INTEGER                  OPTIONAL,
  ///   certReq               [2]    BOOLEAN                  OPTIONAL,
  ///   extensions            [3]    Implicit(Extensions)     OPTIONAL
  /// }
  List<int> _createTimeStampRequest(
    List<int> messageDigest,
    String hashAlgorithm,
    BigInt nonce,
    bool requestCert,
  ) {
    // MessageImprint ::= SEQUENCE {
    //   hashAlgorithm                AlgorithmIdentifier,
    //   hashedMessage                OCTET STRING  }
    final Asn1EncodeCollection messageImprintColl = Asn1EncodeCollection();
    
    // AlgorithmIdentifier
    final Asn1EncodeCollection algIdColl = Asn1EncodeCollection();
    algIdColl.encodableObjects.add(DerObjectID(hashAlgorithm));
    algIdColl.encodableObjects.add(DerNull.value); // Parameters often NULL for hashes
    messageImprintColl.encodableObjects.add(DerSequence(collection: algIdColl));

    // hashedMessage
    messageImprintColl.encodableObjects.add(DerOctet(messageDigest));

    final DerSequence messageImprint = DerSequence(collection: messageImprintColl);

    // TimeStampRequest
    final Asn1EncodeCollection requestColl = Asn1EncodeCollection();
    
    // version = v1(1)
    requestColl.encodableObjects.add(DerInteger.fromNumber(BigInt.one));
    
    // messageImprint
    requestColl.encodableObjects.add(messageImprint);

    // reqPolicy (OPTIONAL) - skipping for basic implementation

    // nonce (OPTIONAL)
    requestColl.encodableObjects.add(DerInteger.fromNumber(nonce));

    // certReq (OPTIONAL)
    if (requestCert) {
      requestColl.encodableObjects.add(DerBoolean(true));
    }
    
    // extensions (OPTIONAL) - not implemented yet

    final DerSequence requestSequence = DerSequence(collection: requestColl);
    return requestSequence.asnEncode()!;
  }

  /// Sends the raw ASN.1 request bytes to the TSA URL via HTTP POST.
  Future<http.Response> _sendRequest(List<int> requestBytes) async {
    final Uri uri = Uri.parse(tsaUrl);
    final Map<String, String> headers = <String, String>{
      'Content-Type': 'application/timestamp-query',
    };

    if (username != null && password != null) {
      final String basicAuth =
          base64Encode(utf8.encode('$username:$password'));
      headers['Authorization'] = 'Basic $basicAuth';
    }

    // Some TSAs might require specific User-Agent or other headers
    // headers['User-Agent'] = 'Dart PDF Library';

    return http.post(
      uri,
      headers: headers,
      body: requestBytes,
    );
  }

  /// Parses the TimeStampResponse and extracts the TimeStampToken (CMS SignedData).
  ///
  /// TimeStampResponse ::= SEQUENCE {
  ///   status                       PKIStatusInfo,
  ///   timeStampToken               TimeStampToken     OPTIONAL  }
  List<int> _extractTokenFromResponse(List<int> responseBytes) {
    final Asn1 asn1 = Asn1Stream(PdfStreamReader(responseBytes)).readAsn1()!;
    if (asn1 is! Asn1Sequence) {
      throw ArgumentError('Invalid TimeStampResponse: not a sequence');
    }
    
    final Asn1Sequence responseSeq = asn1;
    if (responseSeq.count < 2) {
       throw ArgumentError('Invalid TimeStampResponse: missing status OR token');
    }

    // 1. Check Status
    final Asn1 statusObj = responseSeq[0] as Asn1;
    // PKIStatusInfo ::= SEQUENCE {
    //   status        PKIStatus,
    //   statusString  PKIFreeText     OPTIONAL,
    //   failInfo      PKIFailureInfo  OPTIONAL  }
    
    if (statusObj is Asn1Sequence) {
      final Asn1 statusIntObj = statusObj[0] as Asn1;
      if (statusIntObj is DerInteger) {
         final BigInt status = statusIntObj.value;
         if (status != BigInt.zero) { // 0 = granted
             // Try to extract status string if available
             final String errorMsg = 'TSA Request Failed with status: $status';
             if (statusObj.count > 1) {
                // statusString might be here
             }
             throw ArgumentError(errorMsg);
         }
      }
    }

    // 2. Extract timeStampToken
    final Asn1 tokenObj = responseSeq[1] as Asn1;
    // This token is the CMS SignedData structure we need to embed in the PDF
    final List<int>? encoded = (tokenObj as Asn1Encode).getEncoded();
    if (encoded == null) {
      throw ArgumentError('Failed to encode timestamp token');
    }
    return encoded;
  }
}

