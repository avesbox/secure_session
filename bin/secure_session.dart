import 'package:secure_session/secure_session.dart';

void main(List<String> arguments) {
  final secureSession = SecureSession(
    keyPath: 'test_key'
  );
  secureSession['name'] = 'John Doe';
  print(secureSession['name']);
}
