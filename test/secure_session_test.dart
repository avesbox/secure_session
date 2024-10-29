import 'dart:io';
import 'dart:math';

import 'package:secure_session/secure_session.dart';
import 'package:test/test.dart';

void main() {
  group('$SecureSession', () {
    test(
        'if no secret and keyfile provided then an $ArgumentError should be thrown',
        () {
      expect(() => SecureSession(options: []), throwsA(isA<ArgumentError>()));
    });
    test(
        'if a keyfile and salt are provided then a $ArgumentError should be thrown',
        () {
      expect(
          () => SecureSession(options: [
                SessionOptions(
                  keyPath: 'test/keyfile',
                  salt: 'salt',
                )
              ]),
          throwsA(isA<ArgumentError>()));
    });
    test(
        'if a secret and no salt are provided then a $ArgumentError should be thrown',
        () {
      expect(
          () => SecureSession(options: [
                SessionOptions(
                  secret: 'secret',
                )
              ]),
          throwsA(isA<ArgumentError>()));
    });
    test('if a keyfile is provided then the key should be read from the file',
        () {
      final keyPath = 'test/keyfile';
      final keyFile = File(keyPath);
      keyFile.writeAsStringSync('test-key');
      final session = SecureSession(options: [
        SessionOptions(
          keyPath: keyPath,
        )
      ]);
      expect(session.options.first.key, 'test-key');
      keyFile.deleteSync();
    });
    test(
        'if a keyfile is provided but the file does not exist then a $ArgumentError should be thrown',
        () {
      final keyPath = 'test/keyfile-error';
      expect(
          () => SecureSession(options: [
                SessionOptions(
                  keyPath: keyPath,
                )
              ]),
          throwsA(isA<ArgumentError>()));
    });
    test(
        'if a salt and a secret are provided but the salt is shorter than 16 characters then a $ArgumentError should be thrown',
        () {
      expect(
          () => SecureSession(options: [
                SessionOptions(
                    salt: 'short-salt',
                    secret: 'daudhaiuadhiuauihdhuiadhuiadhuiahuidahui')
              ]),
          throwsA(isA<ArgumentError>()));
    });
    test(
        'if a salt and a secret are provided but the secret is shorter than 16 characters then a $ArgumentError should be thrown',
        () {
      var generatedSalt = '';
      for (int i = 0; i < 16; i++) {
        generatedSalt += String.fromCharCode(Random().nextInt(128));
      }
      expect(
          () => SecureSession(options: [
                SessionOptions(salt: generatedSalt, secret: 'short-secret')
              ]),
          throwsA(isA<ArgumentError>()));
    });
    test(
        'if a secret is provided then the key should be equivalent to the secret',
        () {
      var generatedSalt = '';
      for (int i = 0; i < 16; i++) {
        generatedSalt += String.fromCharCode(Random().nextInt(256));
      }
      var generatedSecret = '';
      for (int i = 0; i < 16; i++) {
        generatedSecret += String.fromCharCode(Random().nextInt(256));
      }
      final session = SecureSession(options: [
        SessionOptions(salt: generatedSalt, secret: generatedSecret)
      ]);
      expect(session.options.first.key, generatedSecret);
    });
    test(
        'if a value is passed to the secure session it should be encrypted and saved as a SessionValue',
        () {
      var generatedSalt = '';
      for (int i = 0; i < 16; i++) {
        generatedSalt += String.fromCharCode(Random().nextInt(128));
      }
      var generatedSecret = '';
      for (int i = 0; i < 16; i++) {
        generatedSecret += String.fromCharCode(Random().nextInt(128));
      }
      final session = SecureSession(options: [
        SessionOptions(secret: generatedSecret, salt: generatedSalt)
      ]);
      final value = 'test-value';
      session.write(value, 'session');
      expect(session.read('session'), value);
    });
    test(
        'if a value is passed to a session different from the default session it should be encrypted and saved as a SessionValue',
        () {
      var generatedSalt = '';
      for (int i = 0; i < 16; i++) {
        generatedSalt += String.fromCharCode(Random().nextInt(128));
      }
      var generatedSecret = '';
      for (int i = 0; i < 16; i++) {
        generatedSecret += String.fromCharCode(Random().nextInt(128));
      }
      final session = SecureSession(options: [
        SessionOptions(
            secret: generatedSecret,
            salt: generatedSalt,
            cookieName: 'test-session')
      ]);
      final value = 'test-value';
      session.write('test-session', value);
      expect(session.read('test-session'), value);
    });

    test(
        'if a value is passed and the clear method is called then the read method should return null',
        () {
      var generatedSalt = '';
      for (int i = 0; i < 16; i++) {
        generatedSalt += String.fromCharCode(Random().nextInt(128));
      }
      var generatedSecret = '';
      for (int i = 0; i < 16; i++) {
        generatedSecret += String.fromCharCode(Random().nextInt(128));
      }
      final session = SecureSession(options: [
        SessionOptions(secret: generatedSecret, salt: generatedSalt)
      ]);
      final value = 'test-value';
      session.write(value, 'session');
      session.clear();
      expect(session.read('session'), null);
    });
  });
}
