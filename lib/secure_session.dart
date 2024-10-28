library secure_session;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

/// The length of the salt
const int saltLength = 16;

/// A class to encapsulate the options for a cookie
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

/// A class to manage secure sessions
class SecureSession {
  /// Creates a new instance of [SecureSession]
  SecureSession({
    String? cookieName,
    this.defaultSessionName = 'session',
    this.expiry = const Duration(days: 1),
    String? keyPath,
    this.separator = r';',
    this.secret,
    this.cookieOptions = const CookieOptions(),
    this.salt,
  }) : cookieName = cookieName ?? defaultSessionName {
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
    if (salt != null) {
      if ((salt!.length != saltLength)) {
        throw ArgumentError('Salt must be $saltLength characters long');
      }
      if (Uint8List.fromList(secret!.codeUnits).length != saltLength) {
        throw ArgumentError('Secret must be encoded in UTF-8');
      }
    }
    if (secret != null) {
      if (secret!.length != saltLength) {
        throw ArgumentError('Secret must be $saltLength characters long');
      }
      if (Uint8List.fromList(secret!.codeUnits).length != saltLength) {
        throw ArgumentError('Secret must be encoded in UTF-8');
      }
      _key = secret!;
    }
  }

  /// The name of the cookie
  ///
  /// Default is the value of [defaultSessionName]
  final String? cookieName;

  /// The name of the default session
  final String defaultSessionName;

  /// The separator used to separate the cipher and nonce
  final String separator;

  /// The expiry of the session
  final Duration expiry;

  /// The options for the cookie
  final CookieOptions cookieOptions;

  String? _key;

  /// The key used to encrypt the session
  String? get key {
    return _key;
  }

  /// The secret used to encrypt the session
  final String? secret;

  /// The salt used to encrypt the session
  final String? salt;

  final Map<String, SessionValue> _data = {};

  /// Initializes the session
  ///
  /// [cookies] is a list of cookies
  /// [session] is the current session
  ///
  /// Usable inside your request handler
  void init(List<Cookie> cookies, HttpSession session) {
    final sessionCookie =
        cookies.where((cookie) => cookie.name == cookieName).firstOrNull;
    final sessionValues = cookies.where(
        (cookie) => session.keys.any((session) => session == cookie.name));
    sessionCookie?.domain ??= cookieOptions.domain;
    sessionCookie?.expires ??= cookieOptions.expires;
    sessionCookie?.httpOnly = cookieOptions.httpOnly;
    sessionCookie?.maxAge ??= cookieOptions.maxAge;
    sessionCookie?.path ??= cookieOptions.path;
    sessionCookie?.secure = cookieOptions.secure;
    sessionCookie?.sameSite ??= cookieOptions.sameSite;
    if (sessionCookie != null) {
      final sessionData = sessionCookie.value;
      final sessionValue = decode(sessionData);
      if (sessionValue != null && sessionValue.isNotEmpty) {
        final split = sessionValue.split(separator);
        final value = split[0];
        final ttl =
            DateTime.fromMillisecondsSinceEpoch(int.tryParse(split[1]) ?? 0)
                .difference(DateTime.now())
                .inMilliseconds;
        _data[defaultSessionName] = SessionValue(value, ttl);
      }
    }
    for (final cookie in sessionValues) {
      final sessionValue = decode(cookie.value);
      if (sessionValue != null && sessionValue.isNotEmpty) {
        final split = sessionValue.split(separator);
        final value = split[0];
        final ttl =
            DateTime.fromMillisecondsSinceEpoch(int.tryParse(split[1]) ?? 0)
                .difference(DateTime.now())
                .inMilliseconds;
        _data[cookie.name] = SessionValue(value, ttl);
      }
    }
  }

  /// Writes a value to the session
  ///
  /// [value] can be a string or a json serializable object
  /// [sessionName] is the name of the session to write to (default is the value of [defaultSessionName])
  void write(dynamic value, {String? sessionName}) {
    final name = sessionName ?? defaultSessionName;
    if (value is! String &&
        value is! List<Map<String, dynamic>> &&
        value is! Map<String, dynamic>) {
      throw ArgumentError(
          'Value must be a string or a json serializable object');
    }
    _data[name] = encode(value);
  }

  /// Reads a value from the session
  ///
  /// [sessionName] is the name of the session to read from (default is the value of [defaultSessionName])
  /// Returns the value of the session or null if the session does not exist or has expired
  String? read([String? sessionName]) {
    final name = sessionName ?? defaultSessionName;
    if (!_data.containsKey(name)) {
      return null;
    }
    return decode(_data[name]!.value);
  }

  /// Utility function to decode a value
  ///
  /// [value] is a string to decode
  /// Returns a [String] object
  String? decode(String value) {
    /// Split the value into cipher and nonce
    final splittedValue = value.split(separator);

    /// If the value does not contain a cipher and nonce then return an empty string
    if (splittedValue.length != 2) {
      return null;
    }

    /// Get the cipher and nonce
    final cipher = splittedValue[0];
    final nonceB64 = splittedValue[1];
    final nonce = base64Url.decode(nonceB64);
    if (cipher.isEmpty || nonce.length < 16) {
      return null;
    }
    final encrypter = Fernet(Key.fromUtf8(_key! + utf8.decode(nonce)));

    /// Decrypt the cipher
    final decrypted = encrypter.decrypt(Encrypted.from64(cipher),
        ttl: DateTime.now().add(expiry).millisecondsSinceEpoch);

    /// Split the decrypted value into payload and timestamp
    final separatedPayload = utf8.decode(decrypted).split(separator);
    if (separatedPayload.length != 2) {
      return null;
    }
    final payload = separatedPayload[0];
    final ts = DateTime.now()
        .difference(DateTime.fromMillisecondsSinceEpoch(
            int.tryParse(separatedPayload[1]) ?? 0))
        .inMilliseconds;

    /// If the timestamp is greater than the expiry then return null
    if (ts > expiry.inMilliseconds) {
      return null;
    }
    return payload;
  }

  /// Utility function to encode a value
  ///
  /// [value] is a string or a json serializable object
  /// Returns a [SessionValue] object
  /// Throws an [ArgumentError] if the value already contains the separator
  ///
  /// The value is encrypted using the Fernet algorithm
  SessionValue encode(dynamic value) {
    final msg = value is String ? value : jsonEncode(value);
    if (msg.contains(separator)) {
      throw ArgumentError('Value cannot contain the separator');
    }
    final nonce = salt ?? _generateNonce();
    final encrypter = Fernet(Key.fromUtf8(_key! + nonce));
    final ts = DateTime.now().millisecondsSinceEpoch;
    final cipher = encrypter.encrypt(utf8.encode('$msg\$$ts'));
    return SessionValue(
        '${cipher.base64};${base64Url.encode(nonce.codeUnits)}', ts);
  }

  String _generateNonce() {
    final random = Random.secure();
    final nonce = Uint8List(16);
    for (var i = 0; i < nonce.length; i++) {
      nonce[i] = random.nextInt(256);
    }
    return base64Url.encode(nonce);
  }

  /// Clears the session
  void clear() {
    _data.clear();
  }
}

class SessionValue {
  SessionValue(this.value, this.ttl);

  dynamic value;

  bool hasChanged = false;

  int ttl;
}
