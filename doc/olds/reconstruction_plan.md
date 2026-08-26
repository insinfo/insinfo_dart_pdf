# Reconstruction Plan: Serpro Assinador (Java) to Flutter (insinfo_dart_pdf)

This document details the improved implementation plan to reconstruct the core functionality of the Java-based "Serpro Assinador" using the `insinfo_dart_pdf` library in Dart/Flutter.

## 1. System Overview & Architecture Mapping

The Serpro Assinador functionality revolves around receiving a signature request (DTO), selecting a strategy based on input type (PDF vs Generic), and executing a cryptographic signature (CAdES/PAdES).

| Component | Java Implementation (Source) | Dart Implementation (Target) |
|-----------|------------------------------|------------------------------|
| **Request Model** | `SignRequest` (JSON) | Dart class `SignRequest` |
| **Command Logic** | `Sign.java` / `doCommand()` | `SignatureService.sign(SignRequest)` |
| **PDF Signing** | `WebIntegratedSignature` -> `SignerPDF` | `PdfSigningSession` / `PdfExternalSigning` |
| **Generic Signing** | `Signer` -> `PAdESSigner` (Attached/Detached) | `PdfCmsSigner` (Detached/Attached) |
| **Policy Engine** | `PolicyFactory` (ICP-Brasil defaults) | `PolicyContext` (from `insinfo_dart_pdf`) |

## 2. Data Model Implementation

Replicate the Java `SignRequest` DTO to handle communication with the backend/client.

**Dart Class Structure:**
```dart
class SignRequest {
  final String requestId;
  final String type; // "pdf", "file", "text", "hash", "base64"
  final List<String> inputData; // List of Base64 or Paths
  final String outputDataType; // "file" or "base64"
  final bool attached; // For CMS: Attached vs Detached
  final bool pdfInvisibleSignature;
  final int? pdfStampPage;
  final int? pdfStampPosX;
  final int? pdfStampPosY;
  final String algorithm; // Default "SHA512withRSA"
  // ... other fields from SignRequest.java
}
```

## 3. Core Logic Implementation (`Sign` equivalent)

The logic in `Sign.java` branches primarily on `request.type`.

### Strategy A: PDF Signing (`type == "PDF"`)

In Java, this is handled by `WebIntegratedSignature` delegating to `SignerPDF`.
It creates a visual stamp (if visible) and embeds a CAdES signature.

**Dart Implementation:**
Use `PdfSigningSession`.

1.  **Load PDF:** Read the PDF bytes.
2.  **Visual Stamp (Optional):**
    *   If `!pdfInvisibleSignature`: Use `PdfPage.graphics.drawImage` to draw the stamp at `pdfStampPosX`, `pdfStampPosY`.
    *   *Note:* The Java version has an auto-placement algorithm (`signaturePosition()`) that scans for whitespace. This is complex to port 1:1 without a renderer but can be approximated or omitted in MVP.
3.  **Prepare Signature:**
    *   Create `PdfSignatureOptions`.
    *   Set `PdfSignatureType.signed`.
    *   Use `PdfPkcs7Signer` or `PdfExternalSigner` (for tokens).
4.  **Policy:**
    *   Java uses `AD_RB_CADES` (Reference Basic) or PAdES policies.
    *   Dart: Configure `PdfSignatureValidationOptions` or signature dictionary entries to match ICP-Brasil requirements (LTV, timestamps).
5.  **Output:** Save the signed PDF.

### Strategy B: Generic Content Signing (`type == "file" | "text" | "base64"`)

In Java, this is handled by `signer.doAttachedSign` or `doDetachedSign`.

**Dart Implementation:**
Use `PdfCmsSigner` (despite the name, it handles CMS/PKCS#7).

1.  **Attached (Enveloped):**
    *   Java uses `ContentInfo` wrapping data + sig.
    *   Dart: Use `PdfCmsSigner.signAttached(...)`.
2.  **Detached:**
    *   Java produces just the `SignedData`.
    *   Dart: Use `PdfCmsSigner.signDetached(...)`.
3.  **Input Handling:**
    *   `text`: `utf8.encode(input)`.
    *   `base64`: `base64Decode(input)`.
    *   `file`: Read file bytes.
    *   `hash`: If input is pre-hashed, ensure the signer is configured to skip hashing (Pre-computed hash signing).

## 4. Hardware Token Integration (A3 Certificates)

The Java app uses `SunPKCS11` to talk to smart cards/tokens.

**Dart/Flutter Approach:**
`insinfo_dart_pdf` supports external signing via callbacks (`PdfExternalSigning`).

1.  **Middleware:** You will likely need a Flutter plugin to bridge to native PKCS#11 libraries (like `mypkcs11` or similar) or localized OS stores (Windows `My` store, macOS `Keychain`).
2.  **Flow:**
    *   `PdfSigningSession` halts at the signing step.
    *   Invoke `onSignCallback`.
    *   Pass the digest to the hardware token/OS API.
    *   Return the raw RSA signature bytes.
    *   `insinfo_dart_pdf` embeds these bytes into the CMS/PDF structure.

## 5. Implementation Roadmap

1.  **Base Utilities:**
    *   Implement `SignRequest` parsing.
    *   Create helper for "Policy to OID" mapping (match `PolicyFactory` constants).

2.  **CMS Signer (Non-PDF):**
    *   Implement `GenericSigner` class using `PdfCmsSigner`.
    *   Unit test with Text/Base64 inputs against known valid `p7s` outputs.

3.  **PDF Signer:**
    *   Implement `PdfSignerService`.
    *   Port the Visual Stamp logic (placing image on page).
    *   Integrate `PdfSigningSession` for the crypto operations.

4.  **Integration:**
    *   Create a "Dispatcher" matching `Sign.doCommand` loop.
    *   Handle Batch processing (loop over `inputData`).

## 6. Detailed API Mapping Table

| Java Method / Class | Dart Equivalent | Notes |
|---------------------|-----------------|-------|
| `SignRequest.fromJson()` | `SignRequest.fromJson()` | Standard DTO mapping |
| `Sign.doCommand` | `SignatureDispatcher.dispatch` | Main entry point |
| `SignerPDF` | `PdfSignerService` | Wrapper logic |
| `wis.makeSignature()` | `PdfSigningSession.save()` | Triggers actual signing |
| `signer.doDetachedSign()` | `PdfCmsSigner.signDetached()` | For "text"/"file" inputs |
| `Base64Utils` | `dart:convert` | Built-in |
| `PolicyFactory.Policies` | `IcpBrasilPolicy` (Custom Enum) | Need to Map OIDs |
