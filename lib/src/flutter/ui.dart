/// Built-in types and core primitives for a Flutter application.
///
/// To use, import `dart:ui`.
///
/// This library exposes the lowest-level services that Flutter frameworks use
/// to bootstrap applications, such as classes for driving the input, graphics
/// text, layout, and rendering subsystems.
// @dart = 2.12
// ignore_for_file: unused_import

library dart.ui;

import 'dart:async';
import 'dart:collection' as collection;
import 'dart:convert';
import 'dart:developer' as developer;
//import 'dart:io';
import 'dart:isolate' show SendPort;
import 'dart:math' as math;
//import 'dart:nativewrappers';
import 'dart:typed_data';

part 'geometry.dart';
part 'hash_codes.dart';

part 'lerp.dart';
