/// Writes the SQLCipher fixture of the loaded library's crypto provider:
///
///     dart run test/fixtures/write_sqlcipher_fixture.dart test/fixtures/sqlcipher_<provider>.db [library]
///
/// An Apple build writes `commoncrypto`, every other build `openssl`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:openmls/openmls.dart';

import 'sqlcipher_fixture.dart';

const _suite = MlsCiphersuite.mls128DhkemX25519Aes128GcmSha256Ed25519;

Future<void> main(List<String> args) async {
  final [dbPath, ...libraryPath] = args;
  await Openmls.init(libraryPath: libraryPath.firstOrNull);
  final engine = await MlsEngine.create(
    dbPath: dbPath,
    encryptionKey: sqlcipherFixtureKey,
  );
  final keyPair = MlsSignatureKeyPair.generate(ciphersuite: _suite);
  final signer = serializeSigner(
    ciphersuite: _suite,
    privateKey: keyPair.privateKey(),
    publicKey: keyPair.publicKey(),
  );
  await engine.createGroupWithBuilder(
    config: MlsGroupConfig.defaultConfig(ciphersuite: _suite),
    signerBytes: signer,
    credentialIdentity: utf8.encode('fixture writer'),
    signerPublicKey: keyPair.publicKey(),
    groupId: sqlcipherFixtureGroupId,
  );
  await engine.flexibleCommit(
    groupIdBytes: sqlcipherFixtureGroupId,
    signerBytes: signer,
    options: FlexibleCommitOptions(
      addKeyPackages: const [],
      removeIndices: Uint32List(0),
      forceSelfUpdate: true,
      consumePendingProposals: false,
      createGroupInfo: false,
      useRatchetTreeExtension: true,
    ),
  );
  await engine.close();
}
