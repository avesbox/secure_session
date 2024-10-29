import 'dart:io';

import 'package:secure_session/secure_session.dart';

Future<void> main(List<String> arguments) async {
  final server = await HttpServer.bind(InternetAddress.anyIPv4, 8080);
  print('Listening on localhost:${server.port}');

  await for (HttpRequest request in server) {
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
    secureSession.init(request.cookies);
    secureSession.write('John Doe', 'session');
    request.response.write(secureSession.read('session'));
    await request.response.close();
  }
}
