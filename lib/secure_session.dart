library secure_session;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

const int saltLength = 16;

final class CookieOptions {
  const CookieOptions({
    this.path = '/',
    this.domain,
    this.expires,
    this.maxAge,
    this.secure = false,
    this.httpOnly = true,
    this.sameSite,
  });

  final String path;

  final String? domain;

  final DateTime? expires;

  final int? maxAge;

  final bool secure;

  final bool httpOnly;

  final SameSite? sameSite;
}

class SecureSession {

  SecureSession({
    String? cookieName,
    this.sessionName = 'session',
    this.expiry = const Duration(days: 1),
    String? keyPath,
    this.secret,
    this.cookieOptions = const CookieOptions(),
    this.salt,
  }) : cookieName = cookieName ?? sessionName {
    if (keyPath == null && secret == null) {
      throw ArgumentError('Either key or secret must be provided');
    }
    if (keyPath != null && salt != null) {
      throw ArgumentError('Salt is only used with secret');
    }
    if (keyPath != null) {
      final filePath = File(keyPath);
      if (!filePath.existsSync()) {
        throw ArgumentError('Key file does not exist');
      }
      _key = filePath.readAsStringSync();
    }
    if(salt != null) {
      if((salt!.length != saltLength)) {
        throw ArgumentError('Salt must be $saltLength characters long');
      }
      if(Uint8List.fromList(secret!.codeUnits).length != saltLength) {
        throw ArgumentError('Secret must be encoded in UTF-8');
      }
    }
    if (secret != null) {
      if (secret!.length != saltLength) {
        throw ArgumentError('Secret must be $saltLength characters long');
      }
      if(Uint8List.fromList(secret!.codeUnits).length != saltLength) {
        throw ArgumentError('Secret must be encoded in UTF-8');
      }
      _key = secret!;
    }
  }

  final String? cookieName;

  final String sessionName;

  final Duration expiry;

  final CookieOptions cookieOptions;

  String? _key;

  String? get key {
    return _key;
  }

  final String? secret;

  final String? salt;

  final Map<String, SessionValue> _data = {};


  operator [](String key) {
    if(!_data.containsKey(key)) {
      return null;
    }
    final splittedValue = _data[key]!.value.split(';');
    if(splittedValue.length != 2) {
      return null;
    }
    final cipher = splittedValue[0];
    final nonceB64 = splittedValue[1];
    final nonce = base64Url.decode(nonceB64);
    if(cipher == 0 || nonce.length < 16) {
      return null;
    }
    final encrypter = Fernet(Key.fromUtf8(_key!+utf8.decode(nonce)));
    final decrypted = encrypter.decrypt(Encrypted.from64(cipher), ttl: _data[key]!.ttl);
    return utf8.decode(decrypted);
  }

  operator []=(String key, dynamic value) {
    if(value is! String && value is! List<Map<String, dynamic>> && value is! Map<String, dynamic>) {
      throw ArgumentError('Value must be a string or a json serializable object');
    }
    final msg = value is String ? value : jsonEncode(value);
    final nonce = salt ?? _generateNonce();
    final encrypter = Fernet(Key.fromUtf8(_key!+nonce));
    final cipher = encrypter.encrypt(utf8.encode(msg));
    _data[key] = SessionValue('${cipher.base64};${base64Url.encode(nonce.codeUnits)}', expiry.inMilliseconds);
  }

  String _generateNonce() {
    final random = Random.secure();
    final nonce = Uint8List(16);
    for (var i = 0; i < nonce.length; i++) {
      nonce[i] = random.nextInt(256);
    }
    return base64Url.encode(nonce);
  }

}

class SessionValue {

  SessionValue(this.value, this.ttl);

  dynamic value;

  bool hasChanged = false;

  int ttl;

}