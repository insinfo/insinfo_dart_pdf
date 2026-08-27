import 'dart:math';

import 'cipher_block_chaining_mode.dart';
import 'ipadding.dart';
import '../../../io/pdf_format_exception.dart';

/// internal class
class Pkcs1Encoding implements ICipherBlock {
  /// internal constructor
  Pkcs1Encoding(ICipherBlock? cipher) {
    _cipher = cipher;
  }
  //Fields
  ICipherBlock? _cipher;
  late bool _isEncryption;
  bool? _isPrivateKey;
  late Random _random;
  //Properties
  @override
  String get algorithmName => '${_cipher!.algorithmName!}/PKCS1Padding';
  @override
  int? get inputBlock =>
      _isEncryption ? _cipher!.inputBlock! - 10 : _cipher!.inputBlock;
  @override
  int? get outputBlock =>
      _isEncryption ? _cipher!.outputBlock : _cipher!.outputBlock! - 10;
  //Implmentation
  @override
  void initialize(bool forEncryption, ICipherParameter? parameters) {
    CipherParameter? kParam;
    _random = Random.secure();
    kParam = parameters as CipherParameter?;
    _cipher!.initialize(forEncryption, parameters);
    _isPrivateKey = kParam!.isPrivate;
    _isEncryption = forEncryption;
  }

  @override
  List<int>? processBlock(List<int> input, int inOff, int length) {
    return _isEncryption
        ? encodeBlock(input, inOff, length)
        : decodeBlock(input, inOff, length);
  }

  /// internal method
  List<int>? encodeBlock(List<int> input, int inOff, int inLen) {
    if (inLen > inputBlock!) {
      throw PdfFormatException('Input data too large', source: inLen);
    }
    List<int> block = List<int>.generate(_cipher!.inputBlock!, (int i) => 0);
    if (_isPrivateKey!) {
      block[0] = 0x01;
      for (int i = 1; i != block.length - inLen - 1; i++) {
        block[i] = 0xFF.toUnsigned(8);
      }
    } else {
      block = List<int>.generate(
        _cipher!.inputBlock!,
        (int i) => _random.nextInt(256),
      );
      block[0] = 0x02;
      for (int i = 1; i != block.length - inLen - 1; i++) {
        while (block[i] == 0) {
          block[i] = _random.nextInt(256);
        }
      }
    }
    block[block.length - inLen - 1] = 0x00;
    List.copyRange(block, block.length - inLen, input, inOff, inOff + inLen);
    return _cipher!.processBlock(block, 0, block.length);
  }

  /// internal method
  List<int> decodeBlock(List<int> input, int inOff, int inLen) {
    final List<int> block = _cipher!.processBlock(input, inOff, inLen)!;
    if (block.length < outputBlock!) {
      throw PdfFormatException('Invalid block. Block truncated', source: inLen);
    }
    final int type = block[0];
    if (type != 1 && type != 2) {
      throw PdfFormatException('Invalid block type', source: type);
    }
    if (block.length != _cipher!.outputBlock) {
      throw PdfFormatException('Invalid size', source: type);
    }
    int start;
    for (start = 1; start != block.length; start++) {
      final int pad = block[start];
      if (pad == 0) {
        break;
      }
      if (type == 1 && pad != 0xff.toUnsigned(8)) {
        throw PdfFormatException('Invalid block padding', source: type);
      }
    }
    start++;
    if (start > block.length || start < 10) {
      throw PdfFormatException('no data in block', source: start);
    }
    final List<int> result = List<int>.generate(
      block.length - start,
      (int i) => 0,
    );
    List.copyRange(result, 0, block, start, start + result.length);
    return result;
  }
}
