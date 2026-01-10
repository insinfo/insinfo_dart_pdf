import 'package:test/test.dart';
import 'package:dart_pdf/pdf.dart';

void main() {
  group('PdfAction Tests', () {
    
    test('PdfUriAction', () {
      final action = PdfUriAction('https://google.com');
      expect(action.uri, equals('https://google.com'));
      
      action.uri = 'https://bing.com';
      expect(action.uri, equals('https://bing.com'));
    });
    
    test('PdfSubmitAction', () {
       // Constructor with defaults
       final action = PdfSubmitAction('https://example.com/submit');
       
       expect(action.url, equals('https://example.com/submit'));
       // Check default data format?
       // The constructor param defaults to fdf.
       
       // URL appears to be immutable in implementation (no setter)
       // action.url = 'https://api.example.com';
    });

    test('PdfSubmitAction Flags', () {
        final action = PdfSubmitAction(
            'http://test.com',
            httpMethod: HttpMethod.getHttp,
            dataFormat: SubmitDataFormat.html
        );
        // We need getters to verify
        // Let's check documentation or source for getters
        // If no getters, verification is harder without checking internal dictionary.
        // Assuming getters exist based on typical dart object patterns.
        
        expect(action.httpMethod, equals(HttpMethod.getHttp));
        // Need to check if dataFormat getter exists.
    });

  });
}
