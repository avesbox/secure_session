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
    secret: 'secret',
    cookieName: 'cookie',
  );

  final data = {'key': 'value'};

  session.write(data);

  final result = session.read();

  print(result); // {key: value}
}
```
