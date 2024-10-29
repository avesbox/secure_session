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

  /// The path of the cookie
  final String path;

  /// The domain of the cookie
  final String? domain;

  /// The expiry of the cookie
  final DateTime? expires;

  /// The max age of the cookie
  final int? maxAge;

  /// Whether the cookie is secure
  final bool secure;

  /// Whether the cookie is http only
  final bool httpOnly;

  /// The SameSite attribute of the cookie
  final SameSite? sameSite;
}

/// A class to encapsulate the options for a session
final class SessionOptions {
  /// The name of the session
  final String defaultSessionName;

  /// The name of the cookie
  final Duration expiry;

  /// The separator for the session
  final String separator;

  /// The options for the cookie
  final CookieOptions cookieOptions;

  /// The secret for the session
  final String? secret;

  /// The salt for the session
  final String? salt;

  /// The name of the cookie
  final String? cookieName;

  /// The path to the key
  final String? keyPath;

  late String _key;

  /// The key for the session
  String get key => _key;

  /// Creates a new instance of [SessionOptions]
  SessionOptions({
    this.cookieName,
    this.defaultSessionName = 'session',
    this.expiry = const Duration(days: 1),
    this.keyPath,
    this.separator = r';',
    this.secret,
    this.cookieOptions = const CookieOptions(),
    this.salt,
  }) {
    if (secret == null && keyPath == null) {
      throw ArgumentError('Either secret or keyPath must be provided');
    }
    if (keyPath == null && secret == null) {
      throw ArgumentError('Either key or secret must be provided');
    }
    if (keyPath != null && salt != null) {
      throw ArgumentError('Salt is only used with secret');
    }
    if (keyPath != null) {
      final filePath = File(keyPath!);
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
}

/// A class to manage secure sessions
class SecureSession {
  /// Creates a new instance of [SecureSession]
  SecureSession({required this.options}) {
    if (options.isEmpty) {
      throw ArgumentError('At least one session option must be provided');
    }
  }

  /// The options for the session
  final List<SessionOptions> options;

  final Map<String, SessionValue> _data = {};

  /// Initializes the session
  ///
  /// [cookies] is a list of cookies
  /// [session] is the current session
  ///
  /// Usable inside your request handler
  void init(List<Cookie> cookies) {
    for (final option in options) {
      final cookieName = option.cookieName ?? option.defaultSessionName;
      final sessionCookie =
          cookies.where((cookie) => cookie.name == cookieName).firstOrNull;
      sessionCookie?.domain ??= option.cookieOptions.domain;
      sessionCookie?.expires ??= option.cookieOptions.expires;
      sessionCookie?.httpOnly = option.cookieOptions.httpOnly;
      sessionCookie?.maxAge ??= option.cookieOptions.maxAge;
      sessionCookie?.path ??= option.cookieOptions.path;
      sessionCookie?.secure = option.cookieOptions.secure;
      sessionCookie?.sameSite ??= option.cookieOptions.sameSite;
      if (sessionCookie != null) {
        final sessionData = sessionCookie.value;
        final sessionValue = decode(sessionData, option, false);
        if (sessionValue != null && sessionValue.isNotEmpty) {
          final split = sessionValue.split(option.separator);
          final value = split[0];
          final ttl =
              DateTime.fromMillisecondsSinceEpoch(int.tryParse(split[1]) ?? 0)
                  .difference(DateTime.now())
                  .inMilliseconds;
          _data[cookieName] = SessionValue(value, ttl, option);
        }
      }
    }
  }

  /// Writes a value to the session
  ///
  /// [value] can be a string or a json serializable object
  /// [sessionName] is the name of the session to write to (default is the value of [defaultSessionName])
  void write(dynamic value, String sessionName, [SessionOptions? opts]) {
    final option = options
            .where((e) => (e.cookieName ?? e.defaultSessionName) == sessionName)
            .firstOrNull ??
        opts;
    if (option == null) {
      throw ArgumentError('Session not found');
    }
    final name = (option.cookieName ?? option.defaultSessionName);
    if (value is! String &&
        value is! List<Map<String, dynamic>> &&
        value is! Map<String, dynamic>) {
      throw ArgumentError(
          'Value must be a string or a json serializable object');
    }
    if (_data.containsKey(name)) {
      _data[name]!.deleted = false;
    }
    _data[name] = encode(value, option);
  }

  /// Reads a value from the session and decrypts it
  ///
  /// [sessionName] is the name of the session to read from (default is the value of [defaultSessionName])
  /// Returns the value of the session or null if the session does not exist or has expired
  String? read(String sessionName, [SessionOptions? opts]) {
    final option = opts ?? options
            .where((e) => (e.cookieName ?? e.defaultSessionName) == sessionName)
            .firstOrNull;
    if (option == null) {
      throw ArgumentError('Session not found');
    }
    final session = get(sessionName, option);
    return decode(session!.value, option, session.hasChanged);
  }

  /// Gets a session 
  /// 
  /// It returns a [SessionValue] object
  SessionValue? get(String sessionName, [SessionOptions? opts]) {
    final option = opts ?? options
            .where((e) => (e.cookieName ?? e.defaultSessionName) == sessionName)
            .firstOrNull;
    if (option == null) {
      throw ArgumentError('Session not found');
    }
    final name = (option.cookieName ?? option.defaultSessionName);
    if (!_data.containsKey(name)) {
      return null;
    }
    if (_data[name]!.deleted) {
      return null;
    }
    return _data[name];
  }

  /// Deletes a session
  void delete(String sessionName, [SessionOptions? opts]) {
    final option = options
            .where((e) => (e.cookieName ?? e.defaultSessionName) == sessionName)
            .firstOrNull ??
        opts;
    if (option == null) {
      throw ArgumentError('Session not found');
    }
    final name = (option.cookieName ?? option.defaultSessionName);
    if (!_data.containsKey(name)) {
      return;
    }
    _data[name]!.deleted = true;
  }

  /// Regenerates the session
  void regenerate(String sessionName, [SessionOptions? opts]) {
    final option = options
            .where((e) => (e.cookieName ?? e.defaultSessionName) == sessionName)
            .firstOrNull ??
        opts;
    if (option == null) {
      throw ArgumentError('Session not found');
    }
    final name = (option.cookieName ?? option.defaultSessionName);
    if (!_data.containsKey(name)) {
      return;
    }
    _data[name]!.hasChanged = true;
  }

  /// Utility function to decode a value
  ///
  /// [value] is a string to decode
  /// Returns a [String] object
  String? decode(String value, SessionOptions options, bool hasChanged) {
    /// Split the value into cipher and nonce
    final splittedValue = value.split(options.separator);

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
    final encrypter = Fernet(Key.fromUtf8(options.key + utf8.decode(nonce)));

    /// Decrypt the cipher
    final decrypted = encrypter.decrypt(Encrypted.from64(cipher),
        ttl: DateTime.now().add(options.expiry).millisecondsSinceEpoch);

    /// Split the decrypted value into payload and timestamp
    final separatedPayload = utf8.decode(decrypted).split(options.separator);
    if (separatedPayload.length != 2) {
      return null;
    }
    final payload = separatedPayload[0];
    final ts = DateTime.now()
        .difference(DateTime.fromMillisecondsSinceEpoch(
            int.tryParse(separatedPayload[1]) ?? 0))
        .inMilliseconds;

    /// If the timestamp is greater than the expiry then return null
    if (ts > options.expiry.inMilliseconds && !hasChanged) {
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
  SessionValue encode(dynamic value, SessionOptions options) {
    final msg = value is String ? value : jsonEncode(value);
    if (msg.contains(options.separator)) {
      throw ArgumentError('Value cannot contain the separator');
    }
    final nonce = options.salt ?? _generateNonce();
    final encrypter = Fernet(Key.fromUtf8(options.key + nonce));
    final ts = DateTime.now().millisecondsSinceEpoch;
    final cipher = encrypter.encrypt(utf8.encode('$msg${options.separator}$ts'));
    return SessionValue(
        '${cipher.base64};${base64Url.encode(nonce.codeUnits)}', ts, options);
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

  Map<String, SessionValue> get data => _data;
}

/// A class to encapsulate a session value
class SessionValue {
  /// Creates a new instance of [SessionValue]
  SessionValue(this.value, this.ttl, this.options);

  /// The options for the session
  SessionOptions options;

  /// Whether the session has been deleted
  bool deleted = false;

  /// The value of the session
  dynamic value;

  /// Whether the session has changed
  bool hasChanged = false;

  /// The time to live of the session
  int ttl;
}
