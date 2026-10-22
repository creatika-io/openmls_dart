import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:openmls/openmls.dart';
import 'package:test/test.dart';

import 'test_helpers.dart';

const _mandatoryCiphersuiteCodePoint = 0x0001;
const _basicCredentialType = 1;
const _exporterLabel = 'group flow test';
final _groupId = Uint8List.fromList(utf8.encode('group-flow'));

MlsGroupConfig _plaintextConfig() {
  final defaults = defaultConfig();
  return MlsGroupConfig(
    ciphersuite: defaults.ciphersuite,
    wireFormatPolicy: MlsWireFormatPolicy.plaintext,
    useRatchetTreeExtension: true,
    maxPastEpochs: 0,
    paddingSize: defaults.paddingSize,
    senderRatchetMaxOutOfOrder: defaults.senderRatchetMaxOutOfOrder,
    senderRatchetMaxForwardDistance: defaults.senderRatchetMaxForwardDistance,
    numberOfResumptionPsks: defaults.numberOfResumptionPsks,
  );
}

MlsCapabilities _mandatorySuiteCapabilities() => MlsCapabilities(
  versions: Uint16List(0),
  ciphersuites: Uint16List.fromList([_mandatoryCiphersuiteCodePoint]),
  extensions: Uint16List(0),
  proposals: Uint16List(0),
  credentials: Uint16List.fromList([_basicCredentialType]),
);

FlexibleCommitOptions _commitOptions({
  List<int> removeIndices = const [],
  bool forceSelfUpdate = false,
}) => FlexibleCommitOptions(
  addKeyPackages: const [],
  removeIndices: Uint32List.fromList(removeIndices),
  forceSelfUpdate: forceSelfUpdate,
  consumePendingProposals: false,
  createGroupInfo: true,
  useRatchetTreeExtension: true,
);

void main() {
  late MlsEngine alice;
  late MlsEngine bob;
  late TestIdentity aliceId;
  late TestIdentity bobId;

  setUpAll(Openmls.init);

  setUp(() async {
    alice = await createTestEngine();
    bob = await createTestEngine();
    aliceId = TestIdentity.create('alice');
    bobId = TestIdentity.create('bob');
  });

  tearDown(() async {
    await alice.close();
    await bob.close();
  });

  Future<void> createGroup(MlsEngine engine, TestIdentity identity) =>
      engine.createGroupWithBuilder(
        config: _plaintextConfig(),
        signerBytes: identity.signerBytes,
        credentialIdentity: identity.credentialIdentity,
        signerPublicKey: identity.publicKey,
        groupId: _groupId,
        capabilities: _mandatorySuiteCapabilities(),
        credentialBytes: identity.serializedCredential,
      );

  Future<ExternalJoinResult> joinByExternalCommit(
    MlsEngine engine,
    TestIdentity identity,
    Uint8List groupInfo,
  ) => engine.joinGroupExternalCommitV2(
    config: _plaintextConfig(),
    groupInfoBytes: groupInfo,
    signerBytes: identity.signerBytes,
    credentialIdentity: identity.credentialIdentity,
    signerPublicKey: identity.publicKey,
    skipLifetimeValidation: false,
  );

  Future<Uint8List> exportSecret(MlsEngine engine) => engine.exportSecret(
    groupIdBytes: _groupId,
    label: _exporterLabel,
    context: _groupId,
    keyLength: 32,
  );

  Future<void> aliceCreatesAndBobJoins() async {
    await createGroup(alice, aliceId);
    final groupInfo = await alice.exportGroupInfo(
      groupIdBytes: _groupId,
      signerBytes: aliceId.signerBytes,
    );
    final joined = await joinByExternalCommit(bob, bobId, groupInfo);
    await alice.processMessage(
      groupIdBytes: _groupId,
      messageBytes: joined.commit,
    );
  }

  test('the build executes the mandatory suite', () {
    expect(
      supportedCiphersuites(),
      anyOf(
        equals(const [MlsCiphersuite.mls128DhkemX25519Aes128GcmSha256Ed25519]),
        unorderedEquals(MlsCiphersuite.values),
      ),
    );
  });

  test('serializeSigner writes the JSON shape signers are stored in', () {
    final decoded =
        jsonDecode(utf8.decode(aliceId.signerBytes)) as Map<String, dynamic>;
    expect(decoded.keys, unorderedEquals(['private', 'public', 'scheme']));
    expect(decoded['public'], equals(aliceId.publicKey));
    expect(decoded['scheme'], equals(0x0807));
  });

  test('a basic credential round-trips through its wire form', () {
    final credential = MlsCredential.deserialize(
      bytes: aliceId.serializedCredential,
    );
    expect(credential.identity(), equals(aliceId.credentialIdentity));
  });

  test(
    'a created group starts at epoch 0 with its creator as member',
    () async {
      await createGroup(alice, aliceId);

      expect(await alice.groupIsActive(groupIdBytes: _groupId), isTrue);
      expect(await alice.groupEpoch(groupIdBytes: _groupId), BigInt.zero);
      final members = await alice.groupMembers(groupIdBytes: _groupId);
      expect(members, hasLength(1));
      expect(members.single.signatureKey, equals(aliceId.publicKey));
      expect(
        identityFromCredential(members.single.credential),
        equals(aliceId.credentialIdentity),
      );
    },
  );

  test(
    'an external joiner and the creator agree on the epoch secret',
    () async {
      await createGroup(alice, aliceId);
      final groupInfo = await alice.exportGroupInfo(
        groupIdBytes: _groupId,
        signerBytes: aliceId.signerBytes,
      );
      final joined = await joinByExternalCommit(bob, bobId, groupInfo);

      expect(joined.groupId, equals(_groupId));
      expect(mlsMessageContentType(messageBytes: joined.commit), 'commit');
      expect(mlsMessageExtractEpoch(messageBytes: joined.commit), BigInt.zero);

      final processed = await alice.processMessage(
        groupIdBytes: _groupId,
        messageBytes: joined.commit,
      );
      expect(processed.messageType, ProcessedMessageType.stagedCommit);

      expect(await alice.groupEpoch(groupIdBytes: _groupId), BigInt.one);
      expect(await bob.groupEpoch(groupIdBytes: _groupId), BigInt.one);
      expect(await bob.groupMembers(groupIdBytes: _groupId), hasLength(2));
      final aliceSecret = await exportSecret(alice);
      expect(aliceSecret, hasLength(32));
      expect(await exportSecret(bob), equals(aliceSecret));
    },
  );

  test('a self-update commit moves both members to a new secret', () async {
    await aliceCreatesAndBobJoins();
    final previousSecret = await exportSecret(alice);

    final committed = await bob.flexibleCommit(
      groupIdBytes: _groupId,
      signerBytes: bobId.signerBytes,
      options: _commitOptions(forceSelfUpdate: true),
    );
    await bob.mergePendingCommit(groupIdBytes: _groupId);
    expect(committed.groupInfo, isNotNull);
    expect(mlsMessageExtractEpoch(messageBytes: committed.commit), BigInt.one);

    await alice.processMessage(
      groupIdBytes: _groupId,
      messageBytes: committed.commit,
    );

    expect(await alice.groupEpoch(groupIdBytes: _groupId), BigInt.two);
    expect(await bob.groupEpoch(groupIdBytes: _groupId), BigInt.two);
    final secret = await exportSecret(alice);
    expect(secret, isNot(equals(previousSecret)));
    expect(await exportSecret(bob), equals(secret));
  });

  test('a removed member learns from the commit that it left', () async {
    await aliceCreatesAndBobJoins();
    final members = await alice.groupMembers(groupIdBytes: _groupId);
    final bobLeaf = members.singleWhere(
      (member) => _sameBytes(member.signatureKey, bobId.publicKey),
    );

    final committed = await alice.flexibleCommit(
      groupIdBytes: _groupId,
      signerBytes: aliceId.signerBytes,
      options: _commitOptions(removeIndices: [bobLeaf.index]),
    );
    await bob.processMessage(
      groupIdBytes: _groupId,
      messageBytes: committed.commit,
    );

    expect(await alice.groupMembers(groupIdBytes: _groupId), hasLength(1));
    expect(await bob.groupIsActive(groupIdBytes: _groupId), isFalse);
  });

  test('a deleted group is gone', () async {
    await createGroup(alice, aliceId);
    await alice.deleteGroup(groupIdBytes: _groupId);

    await expectLater(
      alice.groupEpoch(groupIdBytes: _groupId),
      throwsA(anything),
    );
  });

  test('group state survives closing and reopening the engine', () async {
    final directory = Directory.systemTemp.createTempSync('openmls_flow_test');
    addTearDown(() => directory.deleteSync(recursive: true));
    final dbPath = '${directory.path}/mls.db';
    final encryptionKey = testEncryptionKey();

    final first = await MlsEngine.create(
      dbPath: dbPath,
      encryptionKey: encryptionKey,
    );
    await createGroup(first, aliceId);
    final secretBeforeClose = await exportSecret(first);
    await first.close();

    final reopened = await MlsEngine.create(
      dbPath: dbPath,
      encryptionKey: encryptionKey,
    );
    expect(await reopened.groupEpoch(groupIdBytes: _groupId), BigInt.zero);
    expect(await exportSecret(reopened), equals(secretBeforeClose));
    await reopened.close();
  });
}

bool _sameBytes(List<int> first, List<int> second) =>
    first.length == second.length &&
    Iterable<int>.generate(first.length).every((i) => first[i] == second[i]);
