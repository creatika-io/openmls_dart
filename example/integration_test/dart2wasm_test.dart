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

  testWidgets('an external joiner and the creator agree on the epoch secret', (
    tester,
  ) async {
    await Openmls.init();
    final alice = await Member.create('alice');
    final bob = await Member.create('bob');
    final defaults = MlsGroupConfig.defaultConfig(ciphersuite: ciphersuite);
    final config = MlsGroupConfig(
      ciphersuite: ciphersuite,
      wireFormatPolicy: MlsWireFormatPolicy.plaintext,
      useRatchetTreeExtension: true,
      maxPastEpochs: defaults.maxPastEpochs,
      paddingSize: defaults.paddingSize,
      senderRatchetMaxOutOfOrder: defaults.senderRatchetMaxOutOfOrder,
      senderRatchetMaxForwardDistance: defaults.senderRatchetMaxForwardDistance,
      numberOfResumptionPsks: defaults.numberOfResumptionPsks,
    );

    final group = await alice.engine.createGroupWithBuilder(
      config: config,
      signerBytes: alice.signerBytes,
      credentialIdentity: alice.identity,
      signerPublicKey: alice.publicKey,
    );
    final groupInfo = await alice.engine.exportGroupInfo(
      groupIdBytes: group.groupId,
      signerBytes: alice.signerBytes,
    );
    final joined = await bob.engine.joinGroupExternalCommitV2(
      config: config,
      groupInfoBytes: groupInfo,
      signerBytes: bob.signerBytes,
      credentialIdentity: bob.identity,
      signerPublicKey: bob.publicKey,
      skipLifetimeValidation: false,
    );
    await alice.engine.processMessage(
      groupIdBytes: group.groupId,
      messageBytes: joined.commit,
    );

    Future<Uint8List> epochSecret(Member member) => member.engine.exportSecret(
      groupIdBytes: group.groupId,
      label: 'dart2wasm test',
      context: group.groupId,
      keyLength: 32,
    );
    final aliceSecret = await epochSecret(alice);
    expect(aliceSecret, hasLength(32));
    expect(await epochSecret(bob), equals(aliceSecret));
    await alice.engine.close();
    await bob.engine.close();
  });
}
