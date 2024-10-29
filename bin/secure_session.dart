import 'package:secure_session/secure_session.dart';

void main(List<String> arguments) {
  final secureSession = SecureSession(options: [
    SessionOptions(
      cookieName: 'session',
      defaultSessionName: 'session',
      expiry: const Duration(days: 1),
      keyPath: 'example/assets/rsa_key.pem',
      separator: r';',
      secret: 'my secret',
      cookieOptions: CookieOptions(),
      salt: 'salt',
    ),
  ]);
  secureSession.write('John Doe', 'session');
  print(secureSession.read('session'));
}
