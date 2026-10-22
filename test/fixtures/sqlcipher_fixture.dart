/// The SQLCipher databases `sqlcipher_compat_test.dart` opens, one per crypto
/// provider, written by `write_sqlcipher_fixture.dart`.
library;

import 'dart:convert';
import 'dart:typed_data';

const sqlcipherFixtureProviders = ['openssl', 'commoncrypto'];

final sqlcipherFixtureKey = Uint8List.fromList(
  List.generate(32, (index) => index * 7),
);

final sqlcipherFixtureGroupId = Uint8List.fromList(
  utf8.encode('sqlcipher fixture'),
);
