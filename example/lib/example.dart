import 'dart:io';

import 'package:secure_session/secure_session.dart';

Future<void> main(List<String> arguments) async {
  final server = await HttpServer.bind(InternetAddress.anyIPv4, 8080);
  print('Listening on localhost:${server.port}');

  await for (HttpRequest request in server) {
    final secureSession = SecureSession(keyPath: 'test_key');
    secureSession.init(request.cookies, request.session);
    secureSession.write('John Doe');
    request.response.write(secureSession.read());
    await request.response.close();
  }
}
