import 'dart:io';
import 'dart:math';

Future<void> main(List<String> arguments) async {
  final stopwatch = Stopwatch()..start();
  if (arguments.length != 1) {
    print('Usage: dart run secure_session:generate_key <file_name>');
    exit(1);
  }
  final secretKey = _randomHexString(8);
  final file = File(arguments.first);
  await file.writeAsString(secretKey);
  print('Generated secret key in ${stopwatch.elapsedMilliseconds}ms');
  stopwatch.stop();
  exit(0);
}

String _randomHexString(int length) {
  Random random = Random();
  StringBuffer sb = StringBuffer();
  for (var i = 0; i < length; i++) {
    sb.write(random.nextInt(16).toRadixString(16));
  }
  return sb.toString();
}
