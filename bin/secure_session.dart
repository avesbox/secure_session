import 'dart:io';

import 'package:secure_session/secure_session.dart';

void main(List<String> arguments) async {
  final secureSession = SecureSession(options: [
    SessionOptions(
      cookieName: 'session',
      defaultSessionName: 'session',
      expiry: const Duration(seconds: 5),
      separator: r';',
      secret: 'a' * 16,
      cookieOptions: CookieOptions(),
      salt: 'b' * 16,
    ),
  ]);
  secureSession.write('John Doe', 'session');

  HttpServer server = await HttpServer.bind(
    InternetAddress.loopbackIPv4,
    8080,
  );

  secureSession.write('John Doe', 'session');
  await for (HttpRequest request in server) {
    secureSession.init(request.cookies.where((e) => e.name != 'DARTSSID').toList());
    request.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.text;
    for (final option in secureSession.options) {
      final value = secureSession.get(option.cookieName ?? option.defaultSessionName)?.value;
      if(value != null) {
        request.response.cookies.add(
          Cookie(
            option.cookieName ?? option.defaultSessionName,
            value.toString(),
          )..maxAge = option.expiry.inSeconds
          ..expires = DateTime.now().add(option.expiry)
          ..httpOnly = option.cookieOptions.httpOnly
          ..secure = option.cookieOptions.secure
          ..sameSite = option.cookieOptions.sameSite
          ..domain = option.cookieOptions.domain
          ..path = option.cookieOptions.path
        );
      }
    }
    request.response.write('Hello, World!');
    await request.response.close();
  }

}
