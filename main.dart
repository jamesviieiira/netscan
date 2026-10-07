// =============================================================================
// NetScan Pro — Detector de câmeras/microfones na rede (Flutter + Material 3)
//
//  • Varredura da rede (ICMP + TCP) e análise de cada aparelho:
//      - portas de vídeo/DVR, confirmação RTSP, leitura da página web
//      - descoberta ONVIF (WS-Discovery), SSDP/UPnP e mDNS
//      - fabricante por MAC (OUI) e pontuação de risco com os motivos
//  • Redes Wi-Fi próximas com nomes típicos de câmeras
//  • Dispositivos Bluetooth (BLE) próximos
//  • Monitor de sinal Wi-Fi do próprio aparelho
//
// O resultado indica SUSPEITA, não prova. Use apenas em redes suas ou com
// autorização.
// =============================================================================

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:dart_ping/dart_ping.dart';
import 'package:dynamic_color/dynamic_color.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:network_info_plus/network_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';

void main() => runApp(const NetScanApp());

// -----------------------------------------------------------------------------
// APP / TEMA
// -----------------------------------------------------------------------------
class NetScanApp extends StatefulWidget {
  const NetScanApp({super.key});

  @override
  State<NetScanApp> createState() => _NetScanAppState();
}

class _NetScanAppState extends State<NetScanApp> {
  ThemeMode _mode = ThemeMode.system;

  void _toggleTheme(Brightness current) => setState(() {
        _mode = current == Brightness.dark ? ThemeMode.light : ThemeMode.dark;
      });

  ThemeData _theme(ColorScheme scheme) => ThemeData(
        useMaterial3: true,
        colorScheme: scheme,
        cardTheme: CardThemeData(
          elevation: 0,
          color: scheme.surfaceContainerLow,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(28),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: scheme.surfaceContainerHighest.withValues(alpha: 0.5),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(20),
            borderSide: BorderSide.none,
          ),
        ),
      );

  @override
  Widget build(BuildContext context) {
    return DynamicColorBuilder(
      builder: (lightDynamic, darkDynamic) {
        final light =
            lightDynamic ?? ColorScheme.fromSeed(seedColor: Colors.indigo);
        final dark = darkDynamic ??
            ColorScheme.fromSeed(
                seedColor: Colors.indigo, brightness: Brightness.dark);

        return MaterialApp(
          title: 'NetScan Pro',
          debugShowCheckedModeBanner: false,
          themeMode: _mode,
          theme: _theme(light),
          darkTheme: _theme(dark),
          home: HomePage(onToggleTheme: _toggleTheme),
        );
      },
    );
  }
}

// -----------------------------------------------------------------------------
// CONSTANTES DE DETECÇÃO
// -----------------------------------------------------------------------------

class PortInfo {
  final String label;
  final int points;
  final bool video;
  final bool audio;
  const PortInfo(this.label, this.points, {this.video = true, this.audio = false});
}

/// Portas típicas de câmeras, DVRs e áudio, com o peso de cada uma.
const Map<int, PortInfo> _kPortInfo = {
  554: PortInfo('RTSP (transmissão de vídeo)', 35),
  8554: PortInfo('RTSP alternativo', 35),
  10554: PortInfo('RTSP alternativo', 30),
  37777: PortInfo('Dahua (DVR/câmera)', 45),
  37778: PortInfo('Dahua (áudio/vídeo)', 40),
  34567: PortInfo('DVR/câmera XMeye', 45),
  9527: PortInfo('DVR/câmera XMeye', 35),
  8899: PortInfo('câmera IP (ONVIF)', 30),
  2020: PortInfo('ONVIF', 25),
  1935: PortInfo('RTMP (streaming)', 20),
  8000: PortInfo('porta de SDK de câmera (Hikvision)', 10),
  5060: PortInfo('SIP (interfone/áudio)', 20, video: false, audio: true),
  23: PortInfo('Telnet aberto (comum em IoT)', 8, video: false),
};

/// Todas as portas sondadas em cada aparelho.
const List<int> _kProbePorts = [
  21, 22, 23, 80, 81, 82, 443, 554, 1935, 2020, 5000, 5060, 7070, //
  8000, 8001, 8080, 8081, 8443, 8554, 8888, 8899, 9000, 9527, 10554,
  34567, 37777, 37778,
];
const List<int> _kRtspPorts = [554, 8554, 10554];
const List<int> _kWebPorts = [80, 81, 82, 8000, 8001, 8080, 8081, 8888, 9000, 443, 8443];

/// Palavras que indicam câmera/DVR.
final RegExp _camRe = RegExp(
  r'\b(ip ?cam\w*|web ?cam\w*|c[aâ]mera\w*|dvr|nvr|cctv|hikvision\w*|dahua\w*|'
  r'reolink\w*|amcrest\w*|foscam\w*|uniview\w*|hanwha\w*|vivotek\w*|onvif\w*|'
  r'mjpe?g\w*|netcam\w*|surveillance|xmeye|icsee|yoosee|v380\w*|wyze\w*|'
  r'ezviz\w*|imou|tapo\w*|lorex\w*|annke|tiandy|hiseeu|ycc365\w*|ipc|rtsp|axis)\b',
  caseSensitive: false,
);

/// Palavras que indicam microfone/gravador de áudio.
final RegExp _audioRe = RegExp(
  r'\b(mic\w*|microphone|spy\w*|recorder|audio ?bug|intercom|'
  r'baby ?(monitor|cam|phone)\w*|voice ?(recorder|assistant)|gsm ?bug)\b',
  caseSensitive: false,
);

/// Nomes de Wi-Fi típicos de câmeras que criam a própria rede.
final RegExp _camSsidRe = RegExp(
  r'\b(ipc\w*|ipcam\w*|webcam\w*|cam(era)?|cam[-_ ]?\d{2,}|dvr\w*|nvr\w*|'
  r'ycc365\w*|v380\w*|ezviz\w*|hikvision\w*|dahua\w*|reolink\w*|foscam\w*|'
  r'hk[-_]\w*|xm[-_]\w*|tapo[-_ ]?cam\w*|minicam\w*|hdwifi\w*|ptz\w*|spy\w*|'
  r'wifi[-_ ]?cam\w*|yi[-_ ]?(home|cam)\w*|icsee\w*|yoosee\w*)\b',
  caseSensitive: false,
);

class _VendorRule {
  final RegExp re;
  final String text;
  final int points;
  final bool video;
  final bool audio;
  _VendorRule(String pattern, this.text, this.points,
      {this.video = false, this.audio = false})
      : re = RegExp(pattern, caseSensitive: false);
}

final List<_VendorRule> _kVendorRules = [
  _VendorRule(
      r'hikvision|dahua|reolink|amcrest|foscam|uniview|hanwha|vivotek|axis comm|'
      r'ezviz|imou|lorex|swann|annke|tiandy|hiseeu|wyze|arlo|blink|immedia|'
      r'ring llc|eufy',
      'Fabricante de câmeras: {v}',
      50,
      video: true),
  _VendorRule(
      r'hisilicon|ingenic|goke|fullhan|xiongmai|anyka|sigmastar|grain media|nextchip',
      'Chipset comum em câmeras IP baratas: {v}',
      40,
      video: true),
  _VendorRule(r'espressif|tuya|ai-thinker',
      'Chip IoT comum em câmeras/microfones DIY: {v}', 20),
  _VendorRule(r'amazon|nest labs|google',
      'Fabricante de assistentes de voz/câmeras domésticas: {v}', 12,
      audio: true),
];

/// Fabricantes Bluetooth (company ID oficial).
const Map<int, String> _kBleCompanies = {
  0x004C: 'Apple',
  0x0006: 'Microsoft',
  0x0075: 'Samsung',
  0x00E0: 'Google',
  0x0171: 'Amazon',
  0x02E5: 'Espressif',
  0x0059: 'Nordic Semiconductor',
  0x000D: 'Texas Instruments',
  0x038F: 'Xiaomi',
  0x027D: 'Huawei',
  0x0087: 'Garmin',
};

// -----------------------------------------------------------------------------
// MODELOS
// -----------------------------------------------------------------------------
enum DeviceKind { self, gateway, other }

enum Risk { none, low, medium, high }

String _riskLabel(Risk r) => switch (r) {
      Risk.high => 'ALTO',
      Risk.medium => 'MÉDIO',
      Risk.low => 'BAIXO',
      Risk.none => 'SEM SINAIS',
    };

class Finding {
  final String text;
  final int points;
  final bool video;
  final bool audio;
  const Finding(this.text, this.points, {this.video = false, this.audio = false});
}

class WebInfo {
  final int port;
  final bool https;
  final int status;
  final String? title;
  final String? server;
  final String? realm;
  final String? hit; // palavra de câmera encontrada no corpo da página
  WebInfo({
    required this.port,
    required this.https,
    required this.status,
    this.title,
    this.server,
    this.realm,
    this.hit,
  });
}

/// Informações vindas dos protocolos de descoberta (SSDP, ONVIF, mDNS).
class Disc {
  String? onvif;
  final Set<String> ssdp = {};
  final Set<String> mdns = {};
  final Set<String> mdnsHosts = {};
  final Set<String> mdnsTxt = {};
}

class NetDevice {
  final String ip;
  final int latencyMs;
  final DeviceKind kind;
  String? mac;
  String? vendor;
  String? hostname;

  // Resultado da análise
  bool probed = false;
  List<int> openPorts = [];
  final List<WebInfo> web = [];
  bool rtspOk = false;
  String? rtspServer;
  Disc? disc;

  // Pontuação
  int score = 0;
  List<Finding> findings = [];
  bool hasVideo = false;
  bool hasAudio = false;

  NetDevice(this.ip, this.latencyMs, this.kind);

  int get lastOctet => int.tryParse(ip.split('.').last) ?? 0;

  Risk get risk {
    if (score >= 60) return Risk.high;
    if (score >= 30) return Risk.medium;
    if (score >= 15) return Risk.low;
    return Risk.none;
  }

  String? get guess {
    if (score < 30) return null;
    if (hasVideo) return 'Possível câmera';
    if (hasAudio) return 'Possível microfone/áudio';
    return 'Aparelho IoT suspeito';
  }
}

/// Calcula a pontuação de risco e os motivos de um dispositivo.
void evaluateDevice(NetDevice d) {
  final f = <Finding>[];
  void add(String t, int p, {bool video = false, bool audio = false}) =>
      f.add(Finding(t, p, video: video, audio: audio));

  // 1) RTSP confirmado
  if (d.rtspOk) {
    add('Responde ao protocolo de vídeo RTSP'
        '${d.rtspServer != null ? ' (${d.rtspServer})' : ''}', 60,
        video: true);
  }

  // 2) Portas abertas
  for (final p in d.openPorts) {
    final info = _kPortInfo[p];
    if (info == null) continue;
    if (d.rtspOk && _kRtspPorts.contains(p)) continue;
    add('Porta $p aberta — ${info.label}', info.points,
        video: info.video, audio: info.audio);
  }

  // 3) Descoberta (ONVIF / SSDP / mDNS)
  final disc = d.disc;
  if (disc != null) {
    if (disc.onvif != null) {
      add('Anuncia-se como câmera ONVIF (${disc.onvif})', 60, video: true);
    }
    for (final s in disc.ssdp) {
      if (_camRe.hasMatch(s)) {
        add('UPnP/SSDP indica câmera: "$s"', 45, video: true);
        break;
      }
    }
    final svc = disc.mdns.join(' ').toLowerCase();
    if (svc.contains('_axis-video')) {
      add('Serviço mDNS de vídeo (_axis-video)', 50, video: true);
    } else if (svc.contains('_rtsp._tcp')) {
      add('Serviço mDNS de vídeo (_rtsp._tcp)', 45, video: true);
    }
    final mdnsAll = [...disc.mdns, ...disc.mdnsHosts, ...disc.mdnsTxt].join(' ');
    final m = _camRe.firstMatch(mdnsAll);
    if (m != null && !svc.contains('_rtsp._tcp') && !svc.contains('_axis-video')) {
      add('Anúncio mDNS menciona "${m.group(0)}"', 30, video: true);
    }
    final a = _audioRe.firstMatch([...disc.ssdp, mdnsAll].join(' '));
    if (a != null) add('Anúncio na rede menciona "${a.group(0)}"', 25, audio: true);
  }

  // 4) Página web
  for (final w in d.web) {
    final blob = '${w.title ?? ''} ${w.server ?? ''} ${w.realm ?? ''} ${w.hit ?? ''}';
    final m = _camRe.firstMatch(blob);
    if (m != null) {
      add('Página web (porta ${w.port}) menciona "${m.group(0)}"'
          '${w.title != null ? ' — ${w.title}' : ''}', 40, video: true);
      break;
    }
  }
  final servers = d.web.map((w) => (w.server ?? '').toLowerCase()).join(' ');
  final emb = RegExp(
          r'goahead|boa/|thttpd|mini_httpd|uc-httpd|app-webs|dnvrs-webs|nvr-webs|jaws|micro_httpd')
      .firstMatch(servers);
  if (emb != null) {
    add('Servidor web embarcado típico de câmeras/DVRs baratos (${emb.group(0)})', 12,
        video: true);
  }

  // 5) Fabricante (OUI)
  final v = d.vendor;
  if (v != null) {
    for (final rule in _kVendorRules) {
      if (rule.re.hasMatch(v)) {
        add(rule.text.replaceAll('{v}', v), rule.points,
            video: rule.video, audio: rule.audio);
        break;
      }
    }
  }

  // 6) Nome do aparelho
  final names = <String>[
    if (d.hostname != null) d.hostname!,
    ...?d.disc?.mdnsHosts,
  ];
  for (final n in names) {
    if (_camRe.hasMatch(n)) {
      add('Nome do aparelho sugere câmera: "$n"', 30, video: true);
      break;
    }
  }
  for (final n in names) {
    if (_audioRe.hasMatch(n)) {
      add('Nome do aparelho sugere microfone: "$n"', 25, audio: true);
      break;
    }
  }
  if (names.any((n) => RegExp(r'^(esp|tuya)', caseSensitive: false).hasMatch(n))) {
    add('Nome típico de módulo IoT', 12);
  }

  f.sort((a, b) => b.points.compareTo(a.points));
  d.findings = f;
  d.hasVideo = f.any((x) => x.video && x.points >= 20);
  d.hasAudio = f.any((x) => x.audio && x.points >= 20);
  d.score = math.min(100, f.fold<int>(0, (s, x) => s + x.points));
}

class WifiNet {
  final String ssid;
  final String bssid;
  final String caps;
  final int level;
  final int freq;
  int risk = 0; // 0 nenhum, 1 atenção, 2 suspeito
  final List<String> flags = [];

  WifiNet(this.ssid, this.bssid, this.caps, this.level, this.freq);

  bool get open => !RegExp(r'WPA|WEP|SAE|OWE', caseSensitive: false).hasMatch(caps);
  int get percent => (2 * (level + 100)).clamp(0, 100);
  String get band => freq >= 5925 ? '6 GHz' : (freq >= 4900 ? '5 GHz' : '2.4 GHz');
}

class BleDev {
  final String address;
  final String name;
  final int rssi;
  final List<int> mfr;
  final List<String> uuids;
  int risk = 0;
  final List<String> flags = [];
  BleDev(this.address, this.name, this.rssi, this.mfr, this.uuids);

  String get maker =>
      mfr.map((id) => _kBleCompanies[id]).whereType<String>().join(', ');
}

// -----------------------------------------------------------------------------
// FUNÇÕES DE REDE (sondagens)
// -----------------------------------------------------------------------------

Future<bool> _tcpOpen(String ip, int port, {int timeoutMs = 700}) async {
  try {
    final s = await Socket.connect(ip, port,
        timeout: Duration(milliseconds: timeoutMs));
    s.destroy();
    return true;
  } catch (_) {
    return false;
  }
}

/// Envia um "OPTIONS" RTSP (handshake padrão) e vê se o aparelho responde.
Future<({bool ok, String? server})> _rtspProbe(String ip, int port) async {
  Socket? s;
  try {
    s = await Socket.connect(ip, port, timeout: const Duration(seconds: 1));
    s.write('OPTIONS rtsp://$ip:$port/ RTSP/1.0\r\n'
        'CSeq: 1\r\nUser-Agent: NetScanPro\r\n\r\n');
    await s.flush();
    final data = BytesBuilder();
    await for (final chunk in s.timeout(const Duration(milliseconds: 1500),
        onTimeout: (sink) => sink.close())) {
      data.add(chunk);
      if (data.length > 2048) break;
      if (utf8.decode(data.toBytes(), allowMalformed: true).contains('\r\n\r\n')) {
        break;
      }
    }
    final text = utf8.decode(data.toBytes(), allowMalformed: true);
    if (!text.startsWith('RTSP/')) return (ok: false, server: null);
    final m = RegExp(r'^Server:\s*(.+?)\r?$', multiLine: true, caseSensitive: false)
        .firstMatch(text);
    return (ok: true, server: m?.group(1)?.trim());
  } catch (_) {
    return (ok: false, server: null);
  } finally {
    s?.destroy();
  }
}

/// Lê a página inicial (título, servidor, realm de login) de uma porta web.
Future<WebInfo?> _webProbe(String ip, int port) async {
  final https = port == 443 || port == 8443;
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 2)
    ..badCertificateCallback = (_, __, ___) => true
    ..userAgent = 'Mozilla/5.0 NetScanPro';
  try {
    final req = await client
        .getUrl(Uri.parse('${https ? 'https' : 'http'}://$ip:$port/'))
        .timeout(const Duration(seconds: 3));
    req.followRedirects = true;
    req.maxRedirects = 3;
    final res = await req.close().timeout(const Duration(seconds: 3));

    final server = res.headers.value('server');
    final auth = res.headers.value('www-authenticate');
    String? realm;
    if (auth != null) {
      realm = RegExp(r'realm="?([^",]+)"?', caseSensitive: false)
              .firstMatch(auth)
              ?.group(1) ??
          auth;
    }

    final bytes = BytesBuilder();
    await for (final c in res.timeout(const Duration(seconds: 2),
        onTimeout: (sink) => sink.close())) {
      bytes.add(c);
      if (bytes.length > 8192) break;
    }
    final body = utf8.decode(bytes.toBytes(), allowMalformed: true);
    final title = RegExp(r'<title[^>]*>([^<]{1,120})', caseSensitive: false)
        .firstMatch(body)
        ?.group(1)
        ?.trim();
    final hit = _camRe.firstMatch(body)?.group(0);

    return WebInfo(
      port: port,
      https: https,
      status: res.statusCode,
      title: (title == null || title.isEmpty) ? null : title,
      server: server,
      realm: realm,
      hit: hit,
    );
  } catch (_) {
    return null;
  } finally {
    client.close(force: true);
  }
}

class _Packet {
  final List<int> data;
  final String host;
  final int port;
  _Packet(this.data, this.host, this.port);
}

/// Envia pacotes UDP (multicast) e escuta as respostas por [listenFor].
Future<void> _udpExchange({
  required String bindIp,
  required List<_Packet> packets,
  required Duration listenFor,
  required void Function(Datagram dg) onData,
}) async {
  RawDatagramSocket? sock;
  try {
    final s = await RawDatagramSocket.bind(InternetAddress(bindIp), 0);
    sock = s;
    s.listen((e) {
      if (e == RawSocketEvent.read) {
        Datagram? dg = s.receive();
        while (dg != null) {
          try {
            onData(dg);
          } catch (_) {}
          dg = s.receive();
        }
      }
    });
    for (var round = 0; round < 2; round++) {
      for (final p in packets) {
        s.send(p.data, InternetAddress(p.host), p.port);
      }
      await Future.delayed(listenFor ~/ 2);
    }
  } catch (_) {
    // sem rede/multicast bloqueado: segue sem esta fonte
  } finally {
    sock?.close();
  }
}

String? _hdr(String text, String name) {
  final m = RegExp('^$name:[ \\t]*(.+?)\\r?\$', multiLine: true, caseSensitive: false)
      .firstMatch(text);
  return m?.group(1)?.trim();
}

String _uuid() {
  final r = math.Random();
  String h(int n) => List.generate(n, (_) => r.nextInt(16).toRadixString(16)).join();
  return '${h(8)}-${h(4)}-${h(4)}-${h(4)}-${h(12)}';
}

// ---- SSDP / UPnP ----
Future<void> _ssdpDiscover(String bindIp, Disc Function(String) at) async {
  const msg = 'M-SEARCH * HTTP/1.1\r\n'
      'HOST: 239.255.255.250:1900\r\n'
      'MAN: "ssdp:discover"\r\n'
      'MX: 2\r\n'
      'ST: ssdp:all\r\n\r\n';
  final locations = <String, String>{};

  await _udpExchange(
    bindIp: bindIp,
    packets: [_Packet(utf8.encode(msg), '239.255.255.250', 1900)],
    listenFor: const Duration(seconds: 4),
    onData: (dg) {
      final ip = dg.address.address;
      if (ip == bindIp) return;
      final text = utf8.decode(dg.data, allowMalformed: true);
      final d = at(ip);
      final server = _hdr(text, 'SERVER');
      if (server != null && server.isNotEmpty) d.ssdp.add(server);
      final loc = _hdr(text, 'LOCATION');
      if (loc != null) {
        final uri = Uri.tryParse(loc);
        if (uri != null && uri.host == ip) locations[ip] = loc;
      }
    },
  );

  // Lê a descrição XML (nome, fabricante, modelo) de cada aparelho.
  await Future.wait(locations.entries.take(40).map((e) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    try {
      final req = await client
          .getUrl(Uri.parse(e.value))
          .timeout(const Duration(seconds: 3));
      final res = await req.close().timeout(const Duration(seconds: 3));
      final bytes = BytesBuilder();
      await for (final c in res.timeout(const Duration(seconds: 2),
          onTimeout: (sink) => sink.close())) {
        bytes.add(c);
        if (bytes.length > 16384) break;
      }
      final xml = utf8.decode(bytes.toBytes(), allowMalformed: true);
      String? tag(String t) =>
          RegExp('<$t>([^<]*)</$t>', caseSensitive: false).firstMatch(xml)?.group(1)?.trim();
      final parts = [
        tag('friendlyName'),
        tag('manufacturer'),
        tag('modelName'),
        tag('deviceType'),
      ].whereType<String>().where((s) => s.isNotEmpty);
      if (parts.isNotEmpty) at(e.key).ssdp.add(parts.join(' · '));
    } catch (_) {
    } finally {
      client.close(force: true);
    }
  }));
}

// ---- ONVIF (WS-Discovery) ----
Future<void> _onvifDiscover(String bindIp, Disc Function(String) at) async {
  final probe = '<?xml version="1.0" encoding="UTF-8"?>'
      '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
      'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
      'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
      'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
      '<e:Header><w:MessageID>uuid:${_uuid()}</w:MessageID>'
      '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
      '<w:Action e:mustUnderstand="true">'
      'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
      '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>'
      '</e:Envelope>';

  await _udpExchange(
    bindIp: bindIp,
    packets: [_Packet(utf8.encode(probe), '239.255.255.250', 3702)],
    listenFor: const Duration(seconds: 4),
    onData: (dg) {
      final ip = dg.address.address;
      if (ip == bindIp) return;
      final text = utf8.decode(dg.data, allowMalformed: true);
      if (!text.contains('ProbeMatch')) return;
      final scopes = RegExp(r'Scopes[^>]*>([^<]*)<').firstMatch(text)?.group(1) ?? '';
      String? scope(String key) {
        final m = RegExp('onvif://www.onvif.org/$key/([^\\s<]+)').firstMatch(scopes);
        if (m == null) return null;
        try {
          return Uri.decodeComponent(m.group(1)!);
        } catch (_) {
          return m.group(1);
        }
      }

      final info = [scope('name'), scope('hardware')]
          .whereType<String>()
          .where((s) => s.isNotEmpty)
          .join(' · ');
      at(ip).onvif = info.isEmpty ? 'dispositivo ONVIF' : info;
    },
  );
}

// ---- mDNS ----
Uint8List _mdnsQuery(List<String> names) {
  final b = BytesBuilder();
  b.add([0, 0, 0, 0, 0, names.length, 0, 0, 0, 0, 0, 0]);
  for (final n in names) {
    for (final label in n.split('.')) {
      final bytes = utf8.encode(label);
      b.addByte(bytes.length);
      b.add(bytes);
    }
    b.addByte(0);
    b.add([0, 12, 0x80, 0x01]); // PTR, classe IN + "resposta unicast"
  }
  return b.toBytes();
}

(String, int) _readName(Uint8List b, int start) {
  final labels = <String>[];
  var off = start;
  int? end;
  var jumps = 0;
  while (off < b.length) {
    final len = b[off];
    if (len == 0) {
      off += 1;
      break;
    }
    if ((len & 0xC0) == 0xC0) {
      if (off + 1 >= b.length) break;
      final ptr = ((len & 0x3F) << 8) | b[off + 1];
      end ??= off + 2;
      off = ptr;
      if (++jumps > 20) break;
      continue;
    }
    off += 1;
    if (off + len > b.length) break;
    labels.add(utf8.decode(b.sublist(off, off + len), allowMalformed: true));
    off += len;
  }
  return (labels.join('.'), end ?? off);
}

String _cleanMdns(String s) => s.replaceAll(RegExp(r'\.local\.?$'), '');

void _parseMdns(Uint8List b, Disc d) {
  if (b.length < 12) return;
  int u16(int o) => (b[o] << 8) | b[o + 1];
  final qd = u16(4), an = u16(6), ns = u16(8), ar = u16(10);
  var off = 12;
  for (var i = 0; i < qd; i++) {
    off = _readName(b, off).$2 + 4;
  }
  for (var i = 0; i < an + ns + ar; i++) {
    if (off >= b.length) break;
    final (name, next) = _readName(b, off);
    off = next;
    if (off + 10 > b.length) break;
    final type = u16(off);
    final rdlen = u16(off + 8);
    final rd = off + 10;
    off = rd + rdlen;
    if (off > b.length) break;
    switch (type) {
      case 12: // PTR
        {
          final (target, _) = _readName(b, rd);
          d.mdns.add(_cleanMdns(name));
          d.mdns.add(_cleanMdns(target));
        }
      case 33: // SRV
        {
          if (rdlen > 6) {
            final (target, _) = _readName(b, rd + 6);
            d.mdnsHosts.add(_cleanMdns(target));
          }
          d.mdns.add(_cleanMdns(name));
        }
      case 1: // A
        d.mdnsHosts.add(_cleanMdns(name));
      case 16: // TXT
        {
          var p = rd;
          while (p < rd + rdlen && p < b.length) {
            final l = b[p];
            p += 1;
            if (p + l > b.length) break;
            final s = utf8.decode(b.sublist(p, p + l), allowMalformed: true);
            if (RegExp(r'^(md|fn|model|manufacturer|am|ty|product)=',
                    caseSensitive: false)
                .hasMatch(s)) {
              d.mdnsTxt.add(s);
            }
            p += l;
          }
        }
    }
  }
}

Future<void> _mdnsDiscover(String bindIp, Disc Function(String) at) async {
  final q = _mdnsQuery([
    '_services._dns-sd._udp.local',
    '_rtsp._tcp.local',
    '_http._tcp.local',
    '_axis-video._tcp.local',
    '_onvif._tcp.local',
    '_googlecast._tcp.local',
    '_airplay._tcp.local',
    '_hap._tcp.local',
    '_ipp._tcp.local',
    '_raop._tcp.local',
  ]);
  await _udpExchange(
    bindIp: bindIp,
    packets: [_Packet(q, '224.0.0.251', 5353)],
    listenFor: const Duration(seconds: 4),
    onData: (dg) {
      final ip = dg.address.address;
      if (ip == bindIp) return;
      _parseMdns(Uint8List.fromList(dg.data), at(ip));
    },
  );
}

// -----------------------------------------------------------------------------
// TELA ÚNICA
// -----------------------------------------------------------------------------
class HomePage extends StatefulWidget {
  final void Function(Brightness current) onToggleTheme;
  const HomePage({super.key, required this.onToggleTheme});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  // Canal nativo (MainActivity.kt): RSSI, varredura Wi-Fi, BLE e multicast.
  static const _ch = MethodChannel('netscan/wifi');
  final _netInfo = NetworkInfo();

  // ---- Wi-Fi / sinal ----
  Timer? _signalTimer;
  int? _rssi;
  int? _linkSpeed;
  int? _frequency;
  String? _myIp;
  String? _gatewayIp;
  String? _ssid;
  bool _locationDenied = false;

  // ---- Varredura da rede ----
  bool _scanning = false;
  bool _enriching = false;
  double _progress = 0;
  String _phase = '';
  String? _scanError;
  bool _onlySuspects = false;
  final List<NetDevice> _devices = [];
  int _scanToken = 0;

  // ---- Consulta de MAC (campo manual) ----
  final _macController = TextEditingController();
  bool _lookingUp = false;
  String? _vendor;
  String? _lookupMessage;
  bool _randomizedMac = false;
  DateTime _lastLookup = DateTime.fromMillisecondsSinceEpoch(0);

  // ---- Redes Wi-Fi próximas ----
  bool _wifiScanning = false;
  String? _wifiError;
  List<WifiNet> _wifiNets = [];

  // ---- Bluetooth ----
  bool _bleScanning = false;
  String? _bleError;
  List<BleDev> _bleDevs = [];

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  @override
  void dispose() {
    _signalTimer?.cancel();
    _macController.dispose();
    _scanToken++;
    super.dispose();
  }

  Future<void> _bootstrap() async {
    final status = await Permission.locationWhenInUse.request();
    if (mounted) setState(() => _locationDenied = !status.isGranted);
    await _refreshWifi();
    _signalTimer =
        Timer.periodic(const Duration(seconds: 2), (_) => _refreshWifi());
  }

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(
        content: Text(msg),
        behavior: SnackBarBehavior.floating,
        duration: const Duration(seconds: 2),
      ));
  }

  // ===========================================================================
  // MONITOR DE SINAL
  // ===========================================================================
  Future<void> _refreshWifi() async {
    try {
      final info = await _ch.invokeMapMethod<String, dynamic>('getWifiInfo');
      final ip = await _netInfo.getWifiIP();
      final gw = await _netInfo.getWifiGatewayIP();
      String? ssid;
      if (!_locationDenied) {
        ssid = (await _netInfo.getWifiName())?.replaceAll('"', '');
      }
      final rssi = info?['rssi'] as int?;
      if (!mounted) return;
      setState(() {
        _rssi = (rssi == null || rssi <= -127) ? null : rssi;
        _linkSpeed = info?['linkSpeed'] as int?;
        _frequency = info?['frequency'] as int?;
        _myIp = ip;
        _gatewayIp = gw;
        _ssid = (ssid == null || ssid == '<unknown ssid>') ? null : ssid;
      });
    } catch (_) {}
  }

  int _rssiToPercent(int rssi) => (2 * (rssi + 100)).clamp(0, 100);

  ({String label, Color color}) _signalQuality(int rssi) {
    if (rssi >= -50) return (label: 'Excelente', color: Colors.green);
    if (rssi >= -60) return (label: 'Muito bom', color: Colors.lightGreen);
    if (rssi >= -70) return (label: 'Bom', color: Colors.amber);
    if (rssi >= -80) return (label: 'Fraco', color: Colors.orange);
    return (label: 'Muito fraco', color: Colors.red);
  }

  // ===========================================================================
  // VARREDURA DA REDE
  // ===========================================================================
  void _sortDevices() {
    _devices.sort((a, b) {
      final c = b.score.compareTo(a.score);
      return c != 0 ? c : a.lastOctet.compareTo(b.lastOctet);
    });
  }

  NetDevice? _find(String ip) {
    for (final d in _devices) {
      if (d.ip == ip) return d;
    }
    return null;
  }

  Future<void> _startScan() async {
    final token = ++_scanToken;
    setState(() {
      _scanning = true;
      _enriching = false;
      _progress = 0;
      _phase = 'Preparando…';
      _scanError = null;
      _devices.clear();
    });

    final ip = await _netInfo.getWifiIP();
    final gateway = await _netInfo.getWifiGatewayIP();

    if (ip == null || !RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(ip)) {
      setState(() {
        _scanning = false;
        _scanError = 'Não foi possível obter o IP do Wi-Fi. '
            'Conecte-se a uma rede e tente novamente.';
      });
      return;
    }

    final base = ip.split('.').take(3).join('.');

    // Descoberta por protocolos (SSDP, ONVIF, mDNS) em paralelo ao ping.
    final discFuture = _runDiscovery(ip);

    // ---- Fase 1: ping sweep ----
    setState(() => _phase = 'Procurando aparelhos…');
    const batchSize = 24;
    var done = 0;
    for (var start = 1; start <= 254; start += batchSize) {
      if (token != _scanToken || !mounted) return;
      final end = math.min(start + batchSize - 1, 254);
      final batch = [for (var i = start; i <= end; i++) '$base.$i'];

      await Future.wait(batch.map((target) async {
        final latency = await _probeHost(target);
        if (latency != null && token == _scanToken && mounted) {
          final kind = target == ip
              ? DeviceKind.self
              : (target == gateway ? DeviceKind.gateway : DeviceKind.other);
          setState(() {
            _devices.add(NetDevice(target, latency, kind));
            _sortDevices();
          });
        }
      }));

      done += batch.length;
      if (mounted && token == _scanToken) {
        setState(() => _progress = 0.4 * done / 254);
      }
    }
    if (token != _scanToken || !mounted) return;

    // O próprio aparelho nem sempre responde a si mesmo.
    if (_find(ip) == null) {
      _devices.add(NetDevice(ip, 0, DeviceKind.self));
    }

    // ---- Fase 2: junta o que foi anunciado na rede ----
    setState(() {
      _phase = 'Escutando anúncios (UPnP, ONVIF, mDNS)…';
      _progress = 0.4;
    });
    final disc = await discFuture;
    if (token != _scanToken || !mounted) return;

    for (final e in disc.entries) {
      if (!e.key.startsWith('$base.') || e.key == ip) continue;
      var dev = _find(e.key);
      if (dev == null) {
        // Respondeu a anúncios, mas ignorou o ping: também entra na lista.
        dev = NetDevice(
            e.key, 0, e.key == gateway ? DeviceKind.gateway : DeviceKind.other);
        _devices.add(dev);
      }
      dev.disc = e.value;
      if (dev.hostname == null && e.value.mdnsHosts.isNotEmpty) {
        dev.hostname = e.value.mdnsHosts.first;
      }
      evaluateDevice(dev);
    }
    setState(() {
      _sortDevices();
      _progress = 0.5;
    });

    // ---- Fase 3: análise profunda de cada aparelho ----
    final targets =
        _devices.where((d) => d.kind != DeviceKind.self).toList();
    var analysed = 0;
    Future<void> worker() async {
      while (targets.isNotEmpty) {
        if (token != _scanToken || !mounted) return;
        final d = targets.removeLast();
        await _deepProbe(d);
        evaluateDevice(d);
        analysed++;
        if (mounted && token == _scanToken) {
          setState(() {
            _sortDevices();
            _phase = 'Analisando aparelhos… '
                '$analysed/${_devices.length - 1}';
            _progress = 0.5 +
                0.5 * analysed / math.max(1, _devices.length - 1);
          });
        }
      }
    }

    await Future.wait(List.generate(4, (_) => worker()));
    if (token != _scanToken || !mounted) return;

    setState(() {
      _scanning = false;
      _enriching = true;
    });
    unawaited(_enrichDevices(token));
  }

  void _cancelScan() {
    _scanToken++;
    setState(() {
      _scanning = false;
      _enriching = false;
    });
  }

  Future<Map<String, Disc>> _runDiscovery(String bindIp) async {
    final out = <String, Disc>{};
    Disc at(String ip) => out.putIfAbsent(ip, () => Disc());
    try {
      await _ch.invokeMethod('multicast', true);
    } catch (_) {}
    await Future.wait([
      _ssdpDiscover(bindIp, at),
      _onvifDiscover(bindIp, at),
      _mdnsDiscover(bindIp, at),
    ]);
    try {
      await _ch.invokeMethod('multicast', false);
    } catch (_) {}
    return out;
  }

  /// Considera o host "vivo" se responder a ICMP ou a qualquer porta TCP
  /// (inclusive "conexão recusada", que prova que o host existe).
  Future<int?> _probeHost(String ip) async {
    final results = await Future.wait([_tcpProbe(ip), _icmpProbe(ip)]);
    final hits = results.whereType<int>();
    return hits.isEmpty ? null : hits.reduce(math.min);
  }

  Future<int?> _icmpProbe(String ip) async {
    try {
      final ping = Ping(ip, count: 1, timeout: 1);
      await for (final event in ping.stream) {
        final time = event.response?.time;
        if (time != null) return math.max(1, time.inMilliseconds);
      }
    } catch (_) {}
    return null;
  }

  Future<int?> _tcpProbe(String ip) async {
    const ports = [80, 443, 22, 53, 445, 8080, 62078, 5555];
    final results = await Future.wait(ports.map((port) async {
      final sw = Stopwatch()..start();
      try {
        final socket = await Socket.connect(ip, port,
            timeout: const Duration(milliseconds: 600));
        socket.destroy();
        return math.max(1, sw.elapsedMilliseconds);
      } on SocketException catch (e) {
        if (e.osError?.errorCode == 111) {
          return math.max(1, sw.elapsedMilliseconds);
        }
      } catch (_) {}
      return null;
    }));
    final hits = results.whereType<int>();
    return hits.isEmpty ? null : hits.reduce(math.min);
  }

  /// Sonda portas, RTSP e páginas web de um aparelho.
  Future<void> _deepProbe(NetDevice d) async {
    final open = <int>{};
    await Future.wait(_kProbePorts.map((p) async {
      if (await _tcpOpen(d.ip, p)) open.add(p);
    }));
    d.openPorts = open.toList()..sort();

    // RTSP: confirma se a porta fala o protocolo de vídeo.
    d.rtspOk = false;
    d.rtspServer = null;
    for (final p in _kRtspPorts) {
      if (!open.contains(p)) continue;
      final r = await _rtspProbe(d.ip, p);
      if (r.ok) {
        d.rtspOk = true;
        d.rtspServer = r.server;
        break;
      }
    }

    // Páginas web
    d.web.clear();
    final webPorts = _kWebPorts.where(open.contains).take(4).toList();
    final infos = await Future.wait(webPorts.map((p) => _webProbe(d.ip, p)));
    d.web.addAll(infos.whereType<WebInfo>());
    d.probed = true;
  }

  /// ARP (se o Android permitir), nome via DNS reverso e fabricante.
  Future<void> _enrichDevices(int token) async {
    try {
      final lines = await File('/proc/net/arp').readAsLines();
      for (final line in lines.skip(1)) {
        final p = line.trim().split(RegExp(r'\s+'));
        if (p.length >= 4 && p[3] != '00:00:00:00:00:00') {
          final d = _find(p[0]);
          if (d != null) d.mac = p[3].toUpperCase();
        }
      }
    } catch (_) {}
    if (!mounted || token != _scanToken) return;
    setState(() {});

    await Future.wait(List.of(_devices).map((d) async {
      try {
        final r = await InternetAddress(d.ip)
            .reverse()
            .timeout(const Duration(seconds: 2));
        if (r.host != d.ip) d.hostname = r.host;
      } catch (_) {}
    }));
    if (!mounted || token != _scanToken) return;
    for (final d in _devices) {
      evaluateDevice(d);
    }
    setState(_sortDevices);

    for (final d in List.of(_devices)) {
      if (!mounted || token != _scanToken) return;
      if (d.mac != null && d.vendor == null) {
        final r = await _queryVendor(d.mac!);
        if (r.vendor != null) {
          d.vendor = r.vendor;
          evaluateDevice(d);
          if (mounted) setState(_sortDevices);
        }
      }
    }
    if (mounted && token == _scanToken) setState(() => _enriching = false);
  }

  // ===========================================================================
  // CONSULTA DE FABRICANTE (OUI)
  // ===========================================================================
  String _formatMac(String raw) {
    final hex = raw.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toUpperCase();
    final parts = <String>[];
    for (var i = 0; i + 2 <= hex.length && i < 12; i += 2) {
      parts.add(hex.substring(i, i + 2));
    }
    return parts.join(':');
  }

  Future<({String? vendor, String? error, bool randomized})> _queryVendor(
      String raw) async {
    final hex = raw.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toUpperCase();
    if (hex.length < 6) {
      return (
        vendor: null,
        error: 'Digite ao menos os 6 primeiros dígitos do MAC.',
        randomized: false
      );
    }
    final oui = '${hex.substring(0, 2)}:${hex.substring(2, 4)}:'
        '${hex.substring(4, 6)}';
    final randomized = (int.parse(hex.substring(0, 2), radix: 16) & 0x02) != 0;

    final since = DateTime.now().difference(_lastLookup);
    if (since < const Duration(seconds: 1)) {
      await Future.delayed(const Duration(seconds: 1) - since);
    }
    _lastLookup = DateTime.now();

    try {
      final res = await http
          .get(Uri.parse('https://api.macvendors.com/$oui'))
          .timeout(const Duration(seconds: 8));
      if (res.statusCode == 200) {
        return (vendor: res.body.trim(), error: null, randomized: randomized);
      }
      if (res.statusCode == 404) {
        return (
          vendor: null,
          error: randomized
              ? 'MAC privado/aleatório (recurso de privacidade do aparelho): '
                  'não possui fabricante.'
              : 'Fabricante não encontrado para $oui.',
          randomized: randomized
        );
      }
      if (res.statusCode == 429) {
        return (
          vendor: null,
          error: 'Muitas consultas seguidas. Aguarde um instante.',
          randomized: randomized
        );
      }
      return (
        vendor: null,
        error: 'Erro do servidor (${res.statusCode}).',
        randomized: randomized
      );
    } on TimeoutException {
      return (
        vendor: null,
        error: 'Tempo esgotado. Verifique a internet.',
        randomized: randomized
      );
    } catch (_) {
      return (
        vendor: null,
        error: 'Falha de conexão com a API.',
        randomized: randomized
      );
    }
  }

  Future<void> _lookupVendor() async {
    FocusScope.of(context).unfocus();
    setState(() {
      _lookingUp = true;
      _vendor = null;
      _lookupMessage = null;
    });
    final r = await _queryVendor(_macController.text);
    if (!mounted) return;
    setState(() {
      _lookingUp = false;
      _vendor = r.vendor;
      _lookupMessage = r.error;
      _randomizedMac = r.randomized;
    });
  }

  // ===========================================================================
  // REDES WI-FI PRÓXIMAS
  // ===========================================================================
  Future<void> _scanWifiNetworks() async {
    setState(() {
      _wifiScanning = true;
      _wifiError = null;
    });
    try {
      await Permission.locationWhenInUse.request();
      final raw = await _ch.invokeMethod<List<dynamic>>('scanWifi') ?? [];
      final nets = <WifiNet>[];
      for (final e in raw) {
        final m = (e as Map).cast<String, dynamic>();
        final n = WifiNet(
          (m['ssid'] as String?) ?? '',
          (m['bssid'] as String?) ?? '',
          (m['capabilities'] as String?) ?? '',
          (m['level'] as int?) ?? -100,
          (m['frequency'] as int?) ?? 0,
        );
        if (_camSsidRe.hasMatch(n.ssid)) {
          n.risk = 2;
          n.flags.add('Nome típico de câmera com Wi-Fi próprio');
          if (n.open) n.flags.add('Rede aberta (sem senha)');
        } else if (n.ssid.isEmpty) {
          n.risk = 1;
          n.flags.add('Rede oculta (sem nome)');
        }
        nets.add(n);
      }
      nets.sort((a, b) {
        final c = b.risk.compareTo(a.risk);
        return c != 0 ? c : b.level.compareTo(a.level);
      });
      if (!mounted) return;
      setState(() {
        _wifiNets = nets;
        if (nets.isEmpty) {
          _wifiError = 'Nenhuma rede encontrada. Confira se a localização '
              'do aparelho está ligada e a permissão concedida.';
        }
      });
    } on PlatformException catch (e) {
      if (mounted) setState(() => _wifiError = e.message ?? 'Falha na busca.');
    } catch (_) {
      if (mounted) setState(() => _wifiError = 'Falha na busca de redes.');
    } finally {
      if (mounted) setState(() => _wifiScanning = false);
    }
  }

  Future<void> _showWifiDetails(WifiNet n) async {
    final r = await _queryVendor(n.bssid);
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(n.ssid.isEmpty ? '(rede oculta)' : n.ssid),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SelectableText('BSSID: ${n.bssid}'),
            const SizedBox(height: 6),
            Text('Sinal: ${n.level} dBm · ${n.band}'),
            const SizedBox(height: 6),
            Text('Segurança: ${n.open ? 'aberta' : n.caps}'),
            const SizedBox(height: 12),
            Text(r.vendor != null
                ? 'Fabricante: ${r.vendor}'
                : (r.error ?? 'Fabricante desconhecido')),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: n.bssid));
              Navigator.pop(ctx);
              _snack('BSSID copiado');
            },
            child: const Text('Copiar BSSID'),
          ),
          FilledButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Fechar')),
        ],
      ),
    );
  }

  // ===========================================================================
  // BLUETOOTH (BLE)
  // ===========================================================================
  Future<void> _scanBle() async {
    setState(() {
      _bleScanning = true;
      _bleError = null;
      _bleDevs = [];
    });
    try {
      try {
        await [
          Permission.bluetoothScan,
          Permission.bluetoothConnect,
          Permission.locationWhenInUse,
        ].request();
      } catch (_) {}
      final raw = await _ch.invokeMethod<List<dynamic>>('scanBle') ?? [];
      final list = <BleDev>[];
      for (final e in raw) {
        final m = (e as Map).cast<String, dynamic>();
        final dev = BleDev(
          m['address'] as String,
          (m['name'] as String?) ?? '',
          (m['rssi'] as int?) ?? -100,
          ((m['mfr'] as List?) ?? []).map((x) => x as int).toList(),
          ((m['uuids'] as List?) ?? []).map((x) => x.toString()).toList(),
        );
        if (dev.name.isNotEmpty &&
            (_camRe.hasMatch(dev.name) || _audioRe.hasMatch(dev.name))) {
          dev.risk = 2;
          dev.flags.add('Nome sugere câmera/microfone');
        }
        if (dev.mfr.any((id) => id == 0x02E5 || id == 0x0059)) {
          dev.risk = math.max(dev.risk, 1);
          dev.flags.add('Chip comum em dispositivos IoT/escondidos (${dev.maker})');
        }
        if (dev.name.isEmpty && dev.rssi >= -50) {
          dev.risk = math.max(dev.risk, 1);
          dev.flags.add('Sem nome e muito perto (poucos metros)');
        }
        list.add(dev);
      }
      list.sort((a, b) {
        final c = b.risk.compareTo(a.risk);
        return c != 0 ? c : b.rssi.compareTo(a.rssi);
      });
      if (!mounted) return;
      setState(() {
        _bleDevs = list;
        if (list.isEmpty) {
          _bleError = 'Nenhum dispositivo Bluetooth encontrado.';
        }
      });
    } on PlatformException catch (e) {
      if (mounted) {
        setState(() => _bleError = e.message ?? 'Falha na busca Bluetooth.');
      }
    } catch (_) {
      if (mounted) setState(() => _bleError = 'Falha na busca Bluetooth.');
    } finally {
      if (mounted) setState(() => _bleScanning = false);
    }
  }

  // ===========================================================================
  // UI — helpers de cor
  // ===========================================================================
  ({Color bg, Color fg}) _tint(BuildContext c, MaterialColor base) {
    final dark = Theme.of(c).brightness == Brightness.dark;
    return (
      bg: base.withValues(alpha: dark ? 0.28 : 0.2),
      fg: dark ? base.shade100 : base.shade900,
    );
  }

  ({Color bg, Color fg}) _deviceColors(BuildContext c, NetDevice d) {
    final s = Theme.of(c).colorScheme;
    switch (d.risk) {
      case Risk.high:
        return _tint(c, Colors.red);
      case Risk.medium:
        return _tint(c, Colors.deepOrange);
      case Risk.low:
        return _tint(c, Colors.amber);
      case Risk.none:
        break;
    }
    if (d.kind == DeviceKind.self) {
      return (bg: s.primaryContainer, fg: s.onPrimaryContainer);
    }
    if (d.kind == DeviceKind.gateway) {
      return (bg: s.tertiaryContainer, fg: s.onTertiaryContainer);
    }
    return _tint(c, Colors.green);
  }

  // ===========================================================================
  // UI — página
  // ===========================================================================
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final wide = MediaQuery.sizeOf(context).width >= 840;

    return Scaffold(
      backgroundColor: scheme.surface,
      appBar: AppBar(
        backgroundColor: scheme.surface,
        title: const Text('NetScan Pro',
            style: TextStyle(fontWeight: FontWeight.w700)),
        actions: [
          IconButton(
            tooltip: 'Alternar tema',
            icon: Icon(Theme.of(context).brightness == Brightness.dark
                ? Icons.light_mode_rounded
                : Icons.dark_mode_rounded),
            onPressed: () => widget.onToggleTheme(Theme.of(context).brightness),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1200),
              child: wide
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 5,
                          child: Column(children: [
                            _buildSignalCard(context),
                            const SizedBox(height: 16),
                            _buildLookupCard(context),
                            const SizedBox(height: 16),
                            _buildWifiCard(context),
                            const SizedBox(height: 16),
                            _buildBleCard(context),
                          ]),
                        ),
                        const SizedBox(width: 16),
                        Expanded(flex: 6, child: _buildScanCard(context)),
                      ],
                    )
                  : Column(children: [
                      _buildSignalCard(context),
                      const SizedBox(height: 16),
                      _buildScanCard(context),
                      const SizedBox(height: 16),
                      _buildWifiCard(context),
                      const SizedBox(height: 16),
                      _buildBleCard(context),
                      const SizedBox(height: 16),
                      _buildLookupCard(context),
                    ]),
            ),
          ),
        ),
      ),
    );
  }

  Widget _cardHeader(BuildContext context, IconData icon, String title,
      {Widget? trailing}) {
    final scheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        Icon(icon, color: scheme.primary),
        const SizedBox(width: 8),
        Expanded(
          child: Text(title,
              style: Theme.of(context)
                  .textTheme
                  .titleMedium
                  ?.copyWith(fontWeight: FontWeight.w600)),
        ),
        if (trailing != null) trailing,
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // Card: sinal do próprio aparelho
  // ---------------------------------------------------------------------------
  Widget _buildSignalCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final rssi = _rssi;
    final percent = rssi == null ? 0 : _rssiToPercent(rssi);
    final quality = rssi == null ? null : _signalQuality(rssi);
    final color = quality?.color ?? scheme.outline;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            _cardHeader(
              context,
              Icons.wifi_rounded,
              'Sinal deste aparelho',
              trailing: _ssid != null
                  ? Chip(
                      label: Text(_ssid!),
                      avatar: const Icon(Icons.router_rounded, size: 18),
                      visualDensity: VisualDensity.compact,
                    )
                  : null,
            ),
            const SizedBox(height: 20),
            TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: percent / 100),
              duration: const Duration(milliseconds: 600),
              curve: Curves.easeOutCubic,
              builder: (_, value, __) => SizedBox(
                width: 190,
                height: 190,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    SizedBox.expand(
                      child: CircularProgressIndicator(
                        value: value,
                        strokeWidth: 14,
                        strokeCap: StrokeCap.round,
                        backgroundColor: scheme.surfaceContainerHighest,
                        color: color,
                      ),
                    ),
                    Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(rssi == null ? '--' : '$percent%',
                            style: text.displayMedium
                                ?.copyWith(fontWeight: FontWeight.w700)),
                        Text(rssi == null ? 'sem sinal' : '$rssi dBm',
                            style: text.titleMedium
                                ?.copyWith(color: scheme.onSurfaceVariant)),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            if (quality != null)
              Chip(
                label: Text(quality.label),
                backgroundColor: quality.color.withValues(alpha: 0.2),
                side: BorderSide.none,
                labelStyle:
                    TextStyle(color: quality.color, fontWeight: FontWeight.w700),
              ),
            if (_locationDenied) ...[
              const SizedBox(height: 12),
              _InfoBanner(
                icon: Icons.location_off_rounded,
                text: 'Permita a localização para ler o nome da rede (SSID) '
                    'e buscar redes/Bluetooth próximos.',
                action: TextButton(
                  onPressed: openAppSettings,
                  child: const Text('Ajustes'),
                ),
              ),
            ],
            const SizedBox(height: 16),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              alignment: WrapAlignment.center,
              children: [
                _StatPill(Icons.lan_rounded, 'IP', _myIp ?? '—'),
                _StatPill(Icons.router_rounded, 'Gateway', _gatewayIp ?? '—'),
                _StatPill(
                    Icons.speed_rounded,
                    'Link',
                    _linkSpeed == null || _linkSpeed! <= 0
                        ? '—'
                        : '$_linkSpeed Mbps'),
                _StatPill(
                    Icons.waves_rounded,
                    'Banda',
                    _frequency == null || _frequency! <= 0
                        ? '—'
                        : _bandLabel(_frequency!)),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String _bandLabel(int mhz) {
    if (mhz >= 5925) return '6 GHz';
    if (mhz >= 4900) return '5 GHz';
    return '2.4 GHz';
  }

  // ---------------------------------------------------------------------------
  // Card: varredura + detector
  // ---------------------------------------------------------------------------
  Widget _buildScanCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    final probed = _devices.where((d) => d.kind != DeviceKind.self).toList();
    final high = probed.where((d) => d.risk == Risk.high).length;
    final med = probed.where((d) => d.risk == Risk.medium).length;
    final low = probed.where((d) => d.risk == Risk.low).length;
    final visible = _onlySuspects
        ? _devices.where((d) => d.risk != Risk.none).toList()
        : _devices;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _cardHeader(
              context,
              Icons.radar_rounded,
              'Detector de câmeras e microfones',
              trailing: Badge.count(
                count: _devices.length,
                isLabelVisible: _devices.isNotEmpty,
                backgroundColor: scheme.primary,
              ),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: _scanning
                  ? FilledButton.tonalIcon(
                      onPressed: _cancelScan,
                      icon: const Icon(Icons.stop_rounded),
                      label: const Text('Cancelar análise'),
                      style: FilledButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16)),
                    )
                  : FilledButton.icon(
                      onPressed: _startScan,
                      icon: const Icon(Icons.wifi_find_rounded),
                      label: const Text('Analisar rede'),
                      style: FilledButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16)),
                    ),
            ),
            const SizedBox(height: 12),

            AnimatedSize(
              duration: const Duration(milliseconds: 250),
              child: _scanning
                  ? Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          ClipRRect(
                            borderRadius: BorderRadius.circular(8),
                            child: LinearProgressIndicator(
                                value: _progress, minHeight: 8),
                          ),
                          const SizedBox(height: 6),
                          Text('$_phase  ${(_progress * 100).round()}%',
                              style: text.labelMedium
                                  ?.copyWith(color: scheme.onSurfaceVariant)),
                        ],
                      ),
                    )
                  : (_enriching
                      ? Padding(
                          padding: const EdgeInsets.only(bottom: 12),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              ClipRRect(
                                borderRadius: BorderRadius.circular(8),
                                child: const LinearProgressIndicator(
                                    minHeight: 4),
                              ),
                              const SizedBox(height: 6),
                              Text('Consultando MAC e fabricantes…',
                                  style: text.labelMedium?.copyWith(
                                      color: scheme.onSurfaceVariant)),
                            ],
                          ),
                        )
                      : const SizedBox(width: double.infinity)),
            ),

            if (_scanError != null)
              _InfoBanner(icon: Icons.error_outline_rounded, text: _scanError!),

            // Resumo de risco
            if (probed.any((d) => d.probed)) ...[
              Wrap(
                spacing: 8,
                runSpacing: 8,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  _SummaryChip('Alto', high, Colors.red),
                  _SummaryChip('Médio', med, Colors.deepOrange),
                  _SummaryChip('Baixo', low, Colors.amber),
                  FilterChip(
                    label: const Text('Só suspeitos'),
                    selected: _onlySuspects,
                    onSelected: (v) => setState(() => _onlySuspects = v),
                  ),
                ],
              ),
              const SizedBox(height: 12),
            ],

            if (_scanning && _devices.isEmpty)
              Column(
                children: List.generate(
                    3,
                    (_) => const Padding(
                        padding: EdgeInsets.only(bottom: 10),
                        child: _SkeletonTile())),
              ),

            if (!_scanning && _devices.isEmpty && _scanError == null)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 24),
                child: Center(
                  child: Column(
                    children: [
                      Icon(Icons.devices_other_rounded,
                          size: 48, color: scheme.outline),
                      const SizedBox(height: 8),
                      Text('Nenhuma análise realizada ainda',
                          style: text.bodyMedium
                              ?.copyWith(color: scheme.onSurfaceVariant)),
                    ],
                  ),
                ),
              ),

            if (_onlySuspects && visible.isEmpty && _devices.isNotEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 16),
                child: Text(
                    'Nenhum aparelho suspeito encontrado nesta rede. '
                    'Isso não garante que não haja câmeras (veja as limitações abaixo).',
                    style: text.bodyMedium
                        ?.copyWith(color: scheme.onSurfaceVariant)),
              ),

            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: visible.length,
              separatorBuilder: (_, __) => const SizedBox(height: 10),
              itemBuilder: (_, i) => _DeviceTile(
                device: visible[i],
                colors: _deviceColors(context, visible[i]),
                onTap: () => _showDeviceSheet(visible[i]),
              ),
            ),

            const SizedBox(height: 16),
            const _InfoBanner(
              icon: Icons.gpp_maybe_outlined,
              text: 'Indica suspeita, não prova. Câmeras com cartão SD ou chip '
                  '4G não usam o Wi-Fi e não aparecem aqui; redes com '
                  '"isolamento de clientes" (hotéis) escondem os aparelhos. '
                  'Use só em redes suas ou com autorização.',
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Folha de detalhes de um dispositivo
  // ---------------------------------------------------------------------------
  Future<void> _showDeviceSheet(NetDevice d) async {
    final ctrl = TextEditingController(text: d.mac ?? '');
    String? error;
    bool loading = false;
    bool reanalysing = false;

    void copy(String value, String what) {
      Clipboard.setData(ClipboardData(text: value));
      _snack('$what copiado');
    }

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      useSafeArea: true,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSheet) {
          final text = Theme.of(ctx).textTheme;
          final scheme = Theme.of(ctx).colorScheme;
          final colors = _deviceColors(ctx, d);
          final webWithUrl = d.web.isNotEmpty ? d.web.first : null;
          final rtspPort = _kRtspPorts.firstWhere(
              (p) => d.openPorts.contains(p),
              orElse: () => 0);

          Widget section(String title) => Padding(
                padding: const EdgeInsets.only(top: 20, bottom: 8),
                child: Text(title,
                    style: text.titleSmall?.copyWith(
                        color: scheme.primary, fontWeight: FontWeight.w700)),
              );

          Widget kv(String k, String v) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SizedBox(
                        width: 110,
                        child: Text(k,
                            style: text.bodySmall
                                ?.copyWith(color: scheme.onSurfaceVariant))),
                    Expanded(child: SelectableText(v, style: text.bodyMedium)),
                  ],
                ),
              );

          return SingleChildScrollView(
            padding: EdgeInsets.fromLTRB(
                24, 0, 24, 24 + MediaQuery.viewInsetsOf(ctx).bottom),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(d.ip,
                              style: text.headlineSmall
                                  ?.copyWith(fontWeight: FontWeight.w700)),
                          if (d.hostname != null)
                            Text(d.hostname!, style: text.bodyMedium),
                          if (d.guess != null)
                            Text(d.guess!,
                                style: text.titleSmall?.copyWith(
                                    color: colors.fg,
                                    fontWeight: FontWeight.w700)),
                        ],
                      ),
                    ),
                    if (d.kind != DeviceKind.self)
                      _RiskBadge(risk: d.risk, score: d.score, colors: colors),
                  ],
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    FilledButton.tonalIcon(
                      onPressed: () => copy(d.ip, 'IP'),
                      icon: const Icon(Icons.copy_rounded, size: 18),
                      label: const Text('Copiar IP'),
                    ),
                    if (webWithUrl != null)
                      OutlinedButton.icon(
                        onPressed: () => copy(
                            '${webWithUrl.https ? 'https' : 'http'}://${d.ip}:${webWithUrl.port}/',
                            'Endereço web'),
                        icon: const Icon(Icons.language_rounded, size: 18),
                        label: const Text('Copiar URL web'),
                      ),
                    if (rtspPort != 0)
                      OutlinedButton.icon(
                        onPressed: () =>
                            copy('rtsp://${d.ip}:$rtspPort/', 'Endereço RTSP'),
                        icon: const Icon(Icons.videocam_rounded, size: 18),
                        label: const Text('Copiar URL RTSP'),
                      ),
                    if (d.kind != DeviceKind.self)
                      OutlinedButton.icon(
                        onPressed: reanalysing
                            ? null
                            : () async {
                                setSheet(() => reanalysing = true);
                                await _deepProbe(d);
                                evaluateDevice(d);
                                if (mounted) setState(_sortDevices);
                                if (ctx.mounted) {
                                  setSheet(() => reanalysing = false);
                                }
                              },
                        icon: reanalysing
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(
                                    strokeWidth: 2))
                            : const Icon(Icons.refresh_rounded, size: 18),
                        label: const Text('Reanalisar'),
                      ),
                  ],
                ),

                if (d.kind != DeviceKind.self) ...[
                  section('Por que este resultado'),
                  if (d.findings.isEmpty)
                    Text(
                        d.probed
                            ? 'Nenhum sinal de câmera ou microfone encontrado '
                                'neste aparelho. Isso não garante que ele seja inofensivo.'
                            : 'Aparelho ainda não analisado.',
                        style: text.bodyMedium)
                  else
                    ...d.findings.map((f) => Padding(
                          padding: const EdgeInsets.only(bottom: 6),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Icon(
                                  f.video
                                      ? Icons.videocam_rounded
                                      : (f.audio
                                          ? Icons.mic_rounded
                                          : Icons.warning_amber_rounded),
                                  size: 18,
                                  color: colors.fg),
                              const SizedBox(width: 8),
                              Expanded(child: Text(f.text)),
                              const SizedBox(width: 8),
                              Text('+${f.points}',
                                  style: text.labelMedium?.copyWith(
                                      color: scheme.onSurfaceVariant)),
                            ],
                          ),
                        )),

                  section('Detalhes técnicos'),
                  kv('Portas abertas',
                      d.openPorts.isEmpty ? 'nenhuma encontrada' : d.openPorts.join(', ')),
                  if (d.rtspOk)
                    kv('RTSP', 'responde${d.rtspServer != null ? ' — ${d.rtspServer}' : ''}'),
                  for (final w in d.web)
                    kv('Web :${w.port}',
                        [
                          'HTTP ${w.status}',
                          if (w.title != null) 'título "${w.title}"',
                          if (w.server != null) 'servidor ${w.server}',
                          if (w.realm != null) 'login "${w.realm}"',
                        ].join(' · ')),
                  if (d.disc?.onvif != null) kv('ONVIF', d.disc!.onvif!),
                  if (d.disc != null && d.disc!.ssdp.isNotEmpty)
                    kv('UPnP/SSDP', d.disc!.ssdp.join('\n')),
                  if (d.disc != null && d.disc!.mdns.isNotEmpty)
                    kv('mDNS', d.disc!.mdns.take(8).join('\n')),
                  if (d.disc != null && d.disc!.mdnsTxt.isNotEmpty)
                    kv('mDNS (info)', d.disc!.mdnsTxt.take(6).join('\n')),
                  if (d.vendor != null) kv('Fabricante', d.vendor!),
                ],

                section('MAC e fabricante'),
                TextField(
                  controller: ctrl,
                  autocorrect: false,
                  textCapitalization: TextCapitalization.characters,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F:.\-]')),
                    LengthLimitingTextInputFormatter(17),
                  ],
                  decoration: InputDecoration(
                    labelText: 'MAC deste aparelho',
                    hintText: 'AA:BB:CC:DD:EE:FF',
                    prefixIcon: const Icon(Icons.memory_rounded),
                    suffixIcon: IconButton(
                      tooltip: 'Colar',
                      icon: const Icon(Icons.content_paste_rounded),
                      onPressed: () async {
                        final data = await Clipboard.getData('text/plain');
                        if (data?.text != null) {
                          ctrl.text = _formatMac(data!.text!);
                        }
                      },
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: FilledButton.icon(
                        onPressed: loading
                            ? null
                            : () async {
                                setSheet(() {
                                  loading = true;
                                  error = null;
                                });
                                final r = await _queryVendor(ctrl.text);
                                if (!ctx.mounted) return;
                                final formatted = _formatMac(ctrl.text);
                                if (formatted.length >= 8) d.mac = formatted;
                                if (r.vendor != null) {
                                  d.vendor = r.vendor;
                                  evaluateDevice(d); // o fabricante muda a pontuação
                                }
                                if (mounted) setState(_sortDevices);
                                setSheet(() {
                                  loading = false;
                                  error = r.error;
                                });
                              },
                        icon: loading
                            ? const SizedBox(
                                width: 18,
                                height: 18,
                                child:
                                    CircularProgressIndicator(strokeWidth: 2.5))
                            : const Icon(Icons.search_rounded),
                        label: Text(loading ? 'Consultando…' : 'Consultar'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton.icon(
                      onPressed: ctrl.text.trim().isEmpty
                          ? null
                          : () => copy(_formatMac(ctrl.text), 'MAC'),
                      icon: const Icon(Icons.copy_rounded, size: 18),
                      label: const Text('Copiar MAC'),
                    ),
                  ],
                ),
                if (d.vendor != null) _VendorResult(vendor: d.vendor!),
                if (error != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 16),
                    child: _InfoBanner(
                        icon: Icons.info_outline_rounded, text: error!),
                  ),
                const SizedBox(height: 16),
                _InfoBanner(
                  icon: Icons.lightbulb_outline_rounded,
                  text: 'Em Android 10 ou superior o MAC de outros aparelhos '
                      'fica oculto. Veja-o no painel do roteador'
                      '${_gatewayIp != null ? ' (http://$_gatewayIp)' : ''}'
                      ' em "Dispositivos conectados"/"DHCP" e cole aqui.',
                ),
              ],
            ),
          );
        },
      ),
    );
    ctrl.dispose();
  }

  // ---------------------------------------------------------------------------
  // Card: redes Wi-Fi próximas
  // ---------------------------------------------------------------------------
  Widget _buildWifiCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final suspects = _wifiNets.where((n) => n.risk == 2).length;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _cardHeader(context, Icons.wifi_tethering_rounded,
                'Redes Wi-Fi próximas',
                trailing: suspects > 0
                    ? Badge.count(count: suspects, backgroundColor: Colors.red)
                    : null),
            const SizedBox(height: 6),
            Text(
                'Algumas câmeras criam a própria rede (ex.: IPC-1234, HK-xxxx).',
                style:
                    text.bodySmall?.copyWith(color: scheme.onSurfaceVariant)),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: _wifiScanning ? null : _scanWifiNetworks,
                icon: _wifiScanning
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2.5))
                    : const Icon(Icons.search_rounded),
                label: Text(_wifiScanning ? 'Buscando…' : 'Buscar redes'),
                style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14)),
              ),
            ),
            if (_wifiError != null) ...[
              const SizedBox(height: 12),
              _InfoBanner(icon: Icons.info_outline_rounded, text: _wifiError!),
            ],
            const SizedBox(height: 12),
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: _wifiNets.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (_, i) {
                final n = _wifiNets[i];
                final c = n.risk == 2
                    ? _tint(context, Colors.red)
                    : (n.risk == 1
                        ? _tint(context, Colors.amber)
                        : (bg: scheme.surfaceContainerHighest.withValues(alpha: 0.5),
                            fg: scheme.onSurface));
                return _SimpleTile(
                  colors: c,
                  icon: n.risk == 2
                      ? Icons.videocam_rounded
                      : (n.open ? Icons.wifi_rounded : Icons.wifi_lock_rounded),
                  title: n.ssid.isEmpty ? '(rede oculta)' : n.ssid,
                  subtitle: '${n.bssid} · ${n.band}'
                      '${n.open ? ' · aberta' : ''}',
                  flags: n.flags,
                  trailing: '${n.level} dBm',
                  onTap: () => _showWifiDetails(n),
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Card: Bluetooth
  // ---------------------------------------------------------------------------
  Widget _buildBleCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    final suspects = _bleDevs.where((d) => d.risk == 2).length;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _cardHeader(context, Icons.bluetooth_searching_rounded,
                'Bluetooth próximo',
                trailing: suspects > 0
                    ? Badge.count(count: suspects, backgroundColor: Colors.red)
                    : null),
            const SizedBox(height: 6),
            Text(
                'Microfones e gravadores pequenos costumam usar Bluetooth (BLE). '
                'A busca dura cerca de 8 segundos.',
                style:
                    text.bodySmall?.copyWith(color: scheme.onSurfaceVariant)),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: _bleScanning ? null : _scanBle,
                icon: _bleScanning
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2.5))
                    : const Icon(Icons.bluetooth_searching_rounded),
                label: Text(_bleScanning ? 'Buscando…' : 'Buscar dispositivos'),
                style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14)),
              ),
            ),
            if (_bleScanning) ...[
              const SizedBox(height: 12),
              ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: const LinearProgressIndicator(minHeight: 6),
              ),
            ],
            if (_bleError != null) ...[
              const SizedBox(height: 12),
              _InfoBanner(icon: Icons.info_outline_rounded, text: _bleError!),
            ],
            const SizedBox(height: 12),
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: _bleDevs.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (_, i) {
                final d = _bleDevs[i];
                final c = d.risk == 2
                    ? _tint(context, Colors.red)
                    : (d.risk == 1
                        ? _tint(context, Colors.amber)
                        : (bg: scheme.surfaceContainerHighest.withValues(alpha: 0.5),
                            fg: scheme.onSurface));
                return _SimpleTile(
                  colors: c,
                  icon: d.risk == 2
                      ? Icons.mic_rounded
                      : Icons.bluetooth_rounded,
                  title: d.name.isEmpty ? '(sem nome)' : d.name,
                  subtitle: '${d.address}'
                      '${d.maker.isNotEmpty ? ' · ${d.maker}' : ''}',
                  flags: d.flags,
                  trailing: '${d.rssi} dBm',
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: d.address));
                    _snack('Endereço copiado');
                  },
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Card: consulta manual de MAC
  // ---------------------------------------------------------------------------
  Widget _buildLookupCard(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _cardHeader(context, Icons.fingerprint_rounded, 'Fabricante por MAC'),
            const SizedBox(height: 16),
            TextField(
              controller: _macController,
              textInputAction: TextInputAction.search,
              textCapitalization: TextCapitalization.characters,
              autocorrect: false,
              onSubmitted: (_) => _lookupVendor(),
              inputFormatters: [
                FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F:.\-]')),
                LengthLimitingTextInputFormatter(17),
              ],
              decoration: InputDecoration(
                labelText: 'Endereço MAC',
                hintText: 'AA:BB:CC:DD:EE:FF',
                prefixIcon: const Icon(Icons.memory_rounded),
                suffixIcon: IconButton(
                  tooltip: 'Limpar',
                  icon: const Icon(Icons.close_rounded),
                  onPressed: () => setState(() {
                    _macController.clear();
                    _vendor = null;
                    _lookupMessage = null;
                  }),
                ),
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _lookingUp ? null : _lookupVendor,
                icon: _lookingUp
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2.5))
                    : const Icon(Icons.search_rounded),
                label: Text(_lookingUp ? 'Consultando…' : 'Consultar'),
                style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16)),
              ),
            ),
            AnimatedSize(
              duration: const Duration(milliseconds: 300),
              curve: Curves.easeOut,
              alignment: Alignment.topCenter,
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 300),
                child: _vendor != null
                    ? _VendorResult(key: ValueKey(_vendor), vendor: _vendor!)
                    : (_lookupMessage != null
                        ? Padding(
                            key: ValueKey(_lookupMessage),
                            padding: const EdgeInsets.only(top: 16),
                            child: _InfoBanner(
                              icon: Icons.info_outline_rounded,
                              text: _lookupMessage!,
                            ),
                          )
                        : const SizedBox.shrink()),
              ),
            ),
            if (_vendor != null && _randomizedMac)
              const Padding(
                padding: EdgeInsets.only(top: 12),
                child: _InfoBanner(
                  icon: Icons.shield_outlined,
                  text: 'Este MAC é do tipo privado/aleatório; o fabricante '
                      'exibido pode não corresponder ao aparelho real.',
                ),
              ),
          ],
        ),
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// WIDGETS AUXILIARES
// -----------------------------------------------------------------------------

class _RiskBadge extends StatelessWidget {
  final Risk risk;
  final int score;
  final ({Color bg, Color fg}) colors;
  const _RiskBadge(
      {required this.risk, required this.score, required this.colors});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: colors.fg.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        risk == Risk.none ? 'SEM SINAIS' : '${_riskLabel(risk)} · $score',
        style: TextStyle(
            color: colors.fg, fontSize: 11.5, fontWeight: FontWeight.w800),
      ),
    );
  }
}

class _SummaryChip extends StatelessWidget {
  final String label;
  final int count;
  final MaterialColor color;
  const _SummaryChip(this.label, this.count, this.color);

  @override
  Widget build(BuildContext context) {
    final dark = Theme.of(context).brightness == Brightness.dark;
    final fg = dark ? color.shade100 : color.shade900;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: color.withValues(alpha: dark ? 0.28 : 0.2),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Text('$label: $count',
          style: TextStyle(color: fg, fontWeight: FontWeight.w700)),
    );
  }
}

/// Linha de dispositivo da rede, colorida pelo nível de risco.
class _DeviceTile extends StatelessWidget {
  final NetDevice device;
  final ({Color bg, Color fg}) colors;
  final VoidCallback onTap;
  const _DeviceTile(
      {required this.device, required this.colors, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final fg = colors.fg;
    final d = device;

    final IconData icon;
    if (d.kind == DeviceKind.self) {
      icon = Icons.tablet_android_rounded;
    } else if (d.risk != Risk.none && d.hasVideo) {
      icon = Icons.videocam_rounded;
    } else if (d.risk != Risk.none && d.hasAudio) {
      icon = Icons.mic_rounded;
    } else if (d.kind == DeviceKind.gateway) {
      icon = Icons.router_rounded;
    } else {
      icon = Icons.devices_rounded;
    }

    final label = d.kind == DeviceKind.self
        ? 'Este aparelho'
        : (d.guess ??
            (d.kind == DeviceKind.gateway ? 'Roteador / Gateway' : 'Dispositivo'));

    final top = d.findings.isNotEmpty ? d.findings.first.text : null;

    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: 1),
      duration: const Duration(milliseconds: 350),
      curve: Curves.easeOutBack,
      builder: (_, v, child) => Opacity(
        opacity: v.clamp(0, 1),
        child: Transform.translate(offset: Offset(0, (1 - v) * 12), child: child),
      ),
      child: Material(
        color: colors.bg,
        borderRadius: BorderRadius.circular(20),
        child: InkWell(
          borderRadius: BorderRadius.circular(20),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              children: [
                CircleAvatar(
                  backgroundColor: fg.withValues(alpha: 0.12),
                  foregroundColor: fg,
                  child: Icon(icon),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(d.ip,
                          style: TextStyle(
                              color: fg,
                              fontSize: 16,
                              fontWeight: FontWeight.w700,
                              fontFeatures: const [FontFeature.tabularFigures()])),
                      Text(
                          d.hostname != null ? '$label · ${d.hostname}' : label,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                              color: fg.withValues(alpha: 0.8), fontSize: 13)),
                      const SizedBox(height: 2),
                      Row(
                        children: [
                          Icon(
                              d.mac != null
                                  ? Icons.memory_rounded
                                  : Icons.touch_app_rounded,
                              size: 14,
                              color: fg.withValues(alpha: 0.75)),
                          const SizedBox(width: 4),
                          Flexible(
                            child: Text(
                              d.mac != null
                                  ? '${d.mac}${d.vendor != null ? ' · ${d.vendor}' : ''}'
                                  : 'Toque para ver detalhes e informar o MAC',
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                  color: fg.withValues(alpha: 0.85),
                                  fontSize: 12.5,
                                  fontWeight: d.mac != null
                                      ? FontWeight.w600
                                      : FontWeight.w400),
                            ),
                          ),
                        ],
                      ),
                      if (top != null && d.risk != Risk.none)
                        Padding(
                          padding: const EdgeInsets.only(top: 4),
                          child: Text('⚠ $top',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                  color: fg,
                                  fontSize: 12.5,
                                  fontWeight: FontWeight.w600)),
                        ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    if (d.kind != DeviceKind.self && d.probed)
                      _RiskBadge(risk: d.risk, score: d.score, colors: colors),
                    if (d.latencyMs > 0)
                      Padding(
                        padding: const EdgeInsets.only(top: 6),
                        child: Text('${d.latencyMs} ms',
                            style: TextStyle(
                                color: fg, fontWeight: FontWeight.w600)),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Linha genérica usada nas listas de Wi-Fi e Bluetooth.
class _SimpleTile extends StatelessWidget {
  final ({Color bg, Color fg}) colors;
  final IconData icon;
  final String title;
  final String subtitle;
  final List<String> flags;
  final String trailing;
  final VoidCallback onTap;
  const _SimpleTile({
    required this.colors,
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.flags,
    required this.trailing,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final fg = colors.fg;
    return Material(
      color: colors.bg,
      borderRadius: BorderRadius.circular(18),
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          child: Row(
            children: [
              CircleAvatar(
                radius: 20,
                backgroundColor: fg.withValues(alpha: 0.12),
                foregroundColor: fg,
                child: Icon(icon, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            color: fg, fontWeight: FontWeight.w700, fontSize: 15)),
                    Text(subtitle,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            color: fg.withValues(alpha: 0.8), fontSize: 12.5)),
                    for (final f in flags)
                      Text('⚠ $f',
                          style: TextStyle(
                              color: fg,
                              fontSize: 12.5,
                              fontWeight: FontWeight.w600)),
                  ],
                ),
              ),
              Text(trailing,
                  style: TextStyle(color: fg, fontWeight: FontWeight.w600)),
            ],
          ),
        ),
      ),
    );
  }
}

class _SkeletonTile extends StatefulWidget {
  const _SkeletonTile();

  @override
  State<_SkeletonTile> createState() => _SkeletonTileState();
}

class _SkeletonTileState extends State<_SkeletonTile>
    with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1100),
  )..repeat(reverse: true);

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return FadeTransition(
      opacity: Tween(begin: 0.35, end: 1.0).animate(_c),
      child: Container(
        height: 64,
        decoration: BoxDecoration(
          color: scheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(20),
        ),
      ),
    );
  }
}

class _VendorResult extends StatelessWidget {
  final String vendor;
  const _VendorResult({super.key, required this.vendor});

  IconData _iconFor(String v) {
    final s = v.toLowerCase();
    bool has(List<String> keys) => keys.any(s.contains);
    if (has(['hikvision', 'dahua', 'reolink', 'amcrest', 'foscam', 'axis',
        'uniview', 'ezviz', 'wyze', 'arlo', 'lorex', 'hanwha', 'vivotek'])) {
      return Icons.videocam_rounded;
    }
    if (has(['apple'])) return Icons.phone_iphone_rounded;
    if (has(['samsung', 'xiaomi', 'motorola', 'oppo', 'vivo', 'oneplus', 'realme'])) {
      return Icons.smartphone_rounded;
    }
    if (has(['tp-link', 'tplink', 'd-link', 'netgear', 'huawei', 'zte',
        'intelbras', 'ubiquiti', 'mikrotik', 'cisco', 'arris', 'technicolor',
        'aruba'])) {
      return Icons.router_rounded;
    }
    if (has(['intel', 'dell', 'hewlett', 'hp ', 'lenovo', 'asus', 'acer',
        'microsoft', 'realtek', 'liteon', 'azurewave'])) {
      return Icons.laptop_mac_rounded;
    }
    if (has(['sony', 'lg ', 'tcl', 'roku', 'hisense', 'philips', 'vizio'])) {
      return Icons.tv_rounded;
    }
    if (has(['google', 'amazon', 'sonos'])) return Icons.speaker_rounded;
    if (has(['espressif', 'raspberry', 'tuya', 'shelly'])) {
      return Icons.developer_board_rounded;
    }
    if (has(['canon', 'epson', 'brother', 'xerox'])) return Icons.print_rounded;
    return Icons.business_rounded;
  }

  Color _colorFor(String v) {
    final hue = (v.codeUnits.fold<int>(0, (a, b) => (a * 31 + b) & 0xFFFF)) % 360;
    return HSLColor.fromAHSL(1, hue.toDouble(), 0.55, 0.45).toColor();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = _colorFor(vendor);

    return Container(
      margin: const EdgeInsets.only(top: 16),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(24),
      ),
      child: Row(
        children: [
          CircleAvatar(
            radius: 28,
            backgroundColor: color,
            foregroundColor: Colors.white,
            child: Icon(_iconFor(vendor), size: 28),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Fabricante',
                    style: Theme.of(context)
                        .textTheme
                        .labelMedium
                        ?.copyWith(color: scheme.onSurfaceVariant)),
                const SizedBox(height: 2),
                SelectableText(
                  vendor,
                  style: Theme.of(context)
                      .textTheme
                      .titleLarge
                      ?.copyWith(fontWeight: FontWeight.w700),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _StatPill extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  const _StatPill(this.icon, this.label, this.value);

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18, color: scheme.primary),
          const SizedBox(width: 8),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label,
                  style: Theme.of(context)
                      .textTheme
                      .labelSmall
                      ?.copyWith(color: scheme.onSurfaceVariant)),
              Text(value, style: const TextStyle(fontWeight: FontWeight.w600)),
            ],
          ),
        ],
      ),
    );
  }
}

class _InfoBanner extends StatelessWidget {
  final IconData icon;
  final String text;
  final Widget? action;
  const _InfoBanner({required this.icon, required this.text, this.action});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: scheme.secondaryContainer.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(18),
      ),
      child: Row(
        children: [
          Icon(icon, color: scheme.onSecondaryContainer),
          const SizedBox(width: 12),
          Expanded(
            child: Text(text,
                style: TextStyle(color: scheme.onSecondaryContainer)),
          ),
          if (action != null) action!,
        ],
      ),
    );
  }
}
