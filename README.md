# secure_session

Secure stateless cookie session

## Installation

```dart
dart pub add secure_session
```

## Usage

```dart
import 'package:secure_session/secure_session.dart';

void main() {
  final session = SecureSession(
    options: SessionOptions(
      secret: 'secret',
      salt: 'salt',
      cookieName: 'cookie',
    )
  );

  final data = {'key': 'value'};

  session.write(data, 'cookie');

  final result = session.read('cookie');

  print(result); // {key: value}
}
```
