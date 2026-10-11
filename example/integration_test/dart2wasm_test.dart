import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:openmls/openmls.dart';

const ciphersuite = MlsCiphersuite.mls128DhkemX25519Aes128GcmSha256Ed25519;

class Member {
  Member._(this.engine, this.identity, this.signerBytes, this.publicKey);

  final MlsEngine engine;
  final Uint8List identity;
  final Uint8List signerBytes;
  final Uint8List publicKey;

  static Future<Member> create(String name) async {
    final random = Random.secure();
    final storageKey = Uint8List.fromList(
      List.generate(32, (_) => random.nextInt(256)),
    );
    final engine = await MlsEngine.create(
      dbPath: ':memory:',
      encryptionKey: storageKey,
    );
    final keyPair = MlsSignatureKeyPair.generate(ciphersuite: ciphersuite);
    final signerBytes = serializeSigner(
      ciphersuite: ciphersuite,
      privateKey: keyPair.privateKey(),
      publicKey: keyPair.publicKey(),
    );
    return Member._(
      engine,
      Uint8List.fromList(utf8.encode(name)),
      signerBytes,
      keyPair.publicKey(),
    );
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('runs as dart2wasm, not the dart2js fallback', (tester) async {
    expect(kIsWasm, isTrue);
  });

  testWidgets('a welcomed member decrypts an application message', (
    tester,
  ) async {
    await Openmls.init();
    final alice = await Member.create('alice');
    final bob = await Member.create('bob');
    final config = MlsGroupConfig.defaultConfig(ciphersuite: ciphersuite);

    final bobKeyPackage = await bob.engine.createKeyPackage(
      ciphersuite: ciphersuite,
      signerBytes: bob.signerBytes,
      credentialIdentity: bob.identity,
      signerPublicKey: bob.publicKey,
    );
    final group = await alice.engine.createGroup(
      config: config,
      signerBytes: alice.signerBytes,
      credentialIdentity: alice.identity,
      signerPublicKey: alice.publicKey,
    );
    final added = await alice.engine.addMembers(
      groupIdBytes: group.groupId,
      signerBytes: alice.signerBytes,
      keyPackagesBytes: [bobKeyPackage.keyPackageBytes],
    );
    await alice.engine.mergePendingCommit(groupIdBytes: group.groupId);
    final joined = await bob.engine.joinGroupFromWelcome(
      config: config,
      welcomeBytes: added.welcome,
      signerBytes: bob.signerBytes,
    );

    final sent = await alice.engine.createMessage(
      groupIdBytes: group.groupId,
      signerBytes: alice.signerBytes,
      message: utf8.encode('hello bob'),
    );
    final received = await bob.engine.processMessage(
      groupIdBytes: joined.groupId,
      messageBytes: sent.ciphertext,
    );

    expect(utf8.decode(received.applicationMessage!), 'hello bob');
    await alice.engine.close();
    await bob.engine.close();
  });
}
