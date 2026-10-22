@TestOn('vm')
library;

import 'dart:io';

import 'package:openmls/openmls.dart';
import 'package:test/test.dart';

import '../fixtures/sqlcipher_fixture.dart';
import '../test_helpers.dart';

void main() {
  setUpAll(Openmls.init);

  for (final provider in sqlcipherFixtureProviders) {
    test(
      'a database SQLCipher wrote on $provider opens and takes writes',
      () async {
        final directory = Directory.systemTemp.createTempSync('openmls_compat');
        addTearDown(() => directory.deleteSync(recursive: true));
        final dbPath = '${directory.path}/fixture.db';
        File('test/fixtures/sqlcipher_$provider.db').copySync(dbPath);

        final engine = await MlsEngine.create(
          dbPath: dbPath,
          encryptionKey: sqlcipherFixtureKey,
        );
        expect(
          await engine.groupEpoch(groupIdBytes: sqlcipherFixtureGroupId),
          BigInt.one,
        );
        final writer = TestIdentity.create('writer');
        final written = await engine.createGroupWithBuilder(
          config: defaultConfig(),
          signerBytes: writer.signerBytes,
          credentialIdentity: writer.credentialIdentity,
          signerPublicKey: writer.publicKey,
        );
        await engine.close();

        final reopened = await MlsEngine.create(
          dbPath: dbPath,
          encryptionKey: sqlcipherFixtureKey,
        );
        expect(
          await reopened.groupEpoch(groupIdBytes: sqlcipherFixtureGroupId),
          BigInt.one,
        );
        expect(
          await reopened.groupEpoch(groupIdBytes: written.groupId),
          BigInt.zero,
        );
        await reopened.close();
      },
    );
  }
}
