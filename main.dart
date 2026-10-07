// =============================================================================
// NetScan Pro — Single Page App (Flutter + Material 3)
//
//  1) Varredura de rede local (ICMP + sondagem TCP) com lista colorida
//  2) Monitor de sinal Wi-Fi do próprio tablet (RSSI em dBm e %)
//  3) Consulta de fabricante por MAC (OUI) via api.macvendors.com
//  4) Interface Material 3: tema dinâmico, claro/escuro, cards arredondados
// =============================================================================

import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

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
    // DynamicColorBuilder usa as cores do papel de parede (Material You).
    return DynamicColorBuilder(
      builder: (lightDynamic, darkDynamic) {
        final light = lightDynamic ??
            ColorScheme.fromSeed(seedColor: Colors.indigo);
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
// MODELOS
// -----------------------------------------------------------------------------
enum DeviceKind { self, gateway, other }

class NetDevice {
  final String ip;
  final int latencyMs;
  final DeviceKind kind;
  const NetDevice(this.ip, this.latencyMs, this.kind);

  int get lastOctet => int.tryParse(ip.split('.').last) ?? 0;
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
  // Canal nativo (ver MainActivity.kt) para ler o RSSI.
  static const _wifiChannel = MethodChannel('netscan/wifi');
  final _netInfo = NetworkInfo();

  // ---- Estado: Wi-Fi / sinal ----
  Timer? _signalTimer;
  int? _rssi; // dBm
  int? _linkSpeed; // Mbps
  int? _frequency; // MHz
  String? _myIp;
  String? _gatewayIp;
  String? _ssid;
  bool _locationDenied = false;

  // ---- Estado: scan ----
  bool _scanning = false;
  double _progress = 0;
  String? _scanError;
  final List<NetDevice> _devices = [];
  int _scanToken = 0; // permite cancelar um scan em andamento

  // ---- Estado: consulta de MAC ----
  final _macController = TextEditingController();
  bool _lookingUp = false;
  String? _vendor;
  String? _lookupMessage;
  bool _randomizedMac = false;
  DateTime _lastLookup = DateTime.fromMillisecondsSinceEpoch(0);

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

  /// Pede permissão e inicia a atualização periódica do sinal.
  Future<void> _bootstrap() async {
    final status = await Permission.locationWhenInUse.request();
    if (mounted) setState(() => _locationDenied = !status.isGranted);
    await _refreshWifi();
    _signalTimer =
        Timer.periodic(const Duration(seconds: 2), (_) => _refreshWifi());
  }

  // ===========================================================================
  // 2) MONITOR DE SINAL
  // ===========================================================================
  Future<void> _refreshWifi() async {
    try {
      final info =
          await _wifiChannel.invokeMapMethod<String, dynamic>('getWifiInfo');
      final ip = await _netInfo.getWifiIP();
      final gw = await _netInfo.getWifiGatewayIP();
      String? ssid;
      if (!_locationDenied) {
        ssid = (await _netInfo.getWifiName())?.replaceAll('"', '');
      }
      final rssi = info?['rssi'] as int?;
      if (!mounted) return;
      setState(() {
        // -127 = valor "desconhecido" do Android.
        _rssi = (rssi == null || rssi <= -127) ? null : rssi;
        _linkSpeed = info?['linkSpeed'] as int?;
        _frequency = info?['frequency'] as int?;
        _myIp = ip;
        _gatewayIp = gw;
        _ssid = (ssid == null || ssid == '<unknown ssid>') ? null : ssid;
      });
    } catch (_) {
      // Sem Wi-Fi ou canal indisponível: mantém a UI estável.
    }
  }

  /// Converte dBm em porcentagem (0–100). -50 dBm ≈ 100%, -100 dBm ≈ 0%.
  int _rssiToPercent(int rssi) => (2 * (rssi + 100)).clamp(0, 100);

  ({String label, Color color}) _signalQuality(int rssi) {
    if (rssi >= -50) return (label: 'Excelente', color: Colors.green);
    if (rssi >= -60) return (label: 'Muito bom', color: Colors.lightGreen);
    if (rssi >= -70) return (label: 'Bom', color: Colors.amber);
    if (rssi >= -80) return (label: 'Fraco', color: Colors.orange);
    return (label: 'Muito fraco', color: Colors.red);
  }

  // ===========================================================================
  // 1) VARREDURA DE REDE
  // ===========================================================================
  Future<void> _startScan() async {
    final token = ++_scanToken;
    setState(() {
      _scanning = true;
      _progress = 0;
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

    // Assume sub-rede /24 (a mais comum em redes domésticas).
    final base = ip.split('.').take(3).join('.');
    const batchSize = 24; // limita sockets simultâneos
    var done = 0;

    for (var start = 1; start <= 254; start += batchSize) {
      if (token != _scanToken || !mounted) return; // cancelado

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
            _devices.sort((a, b) => a.lastOctet.compareTo(b.lastOctet));
          });
        }
      }));

      done += batch.length;
      if (mounted && token == _scanToken) {
        setState(() => _progress = done / 254);
      }
    }

    // O próprio tablet nem sempre responde a si mesmo: garante na lista.
    if (mounted && token == _scanToken) {
      if (!_devices.any((d) => d.ip == ip)) {
        _devices.add(NetDevice(ip, 0, DeviceKind.self));
        _devices.sort((a, b) => a.lastOctet.compareTo(b.lastOctet));
      }
      setState(() => _scanning = false);
    }
  }

  void _cancelScan() {
    _scanToken++;
    setState(() => _scanning = false);
  }

  /// Considera o host "vivo" se responder a ICMP *ou* a qualquer porta TCP
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
        // 111 = ECONNREFUSED: o host respondeu, só a porta está fechada.
        if (e.osError?.errorCode == 111) {
          return math.max(1, sw.elapsedMilliseconds);
        }
      } catch (_) {}
      return null;
    }));
    final hits = results.whereType<int>();
    return hits.isEmpty ? null : hits.reduce(math.min);
  }

  // ===========================================================================
  // 3) CONSULTA DE FABRICANTE (OUI)
  // ===========================================================================
  Future<void> _lookupVendor() async {
    FocusScope.of(context).unfocus();

    // Normaliza: aceita AA:BB:CC:DD:EE:FF, AA-BB-..., AABB.CCDD..., ou só o OUI.
    final hex = _macController.text
        .replaceAll(RegExp(r'[^0-9a-fA-F]'), '')
        .toUpperCase();

    if (hex.length < 6) {
      setState(() {
        _vendor = null;
        _randomizedMac = false;
        _lookupMessage = 'Digite ao menos os 6 primeiros dígitos do MAC.';
      });
      return;
    }

    final oui = '${hex.substring(0, 2)}:${hex.substring(2, 4)}:'
        '${hex.substring(4, 6)}';

    // MAC aleatório (privado): bit "localmente administrado" ligado.
    final firstByte = int.parse(hex.substring(0, 2), radix: 16);
    final randomized = (firstByte & 0x02) != 0;

    // A API gratuita limita a ~1 requisição por segundo.
    final since = DateTime.now().difference(_lastLookup);
    if (since < const Duration(seconds: 1)) {
      await Future.delayed(const Duration(seconds: 1) - since);
    }
    _lastLookup = DateTime.now();

    setState(() {
      _lookingUp = true;
      _vendor = null;
      _lookupMessage = null;
      _randomizedMac = randomized;
    });

    try {
      final res = await http
          .get(Uri.parse('https://api.macvendors.com/$oui'))
          .timeout(const Duration(seconds: 8));

      if (!mounted) return;
      setState(() {
        if (res.statusCode == 200) {
          _vendor = res.body.trim();
        } else if (res.statusCode == 404) {
          _lookupMessage = randomized
              ? 'Este MAC parece ser privado/aleatório (recurso de '
                  'privacidade do Android/iOS), por isso não tem fabricante.'
              : 'Fabricante não encontrado para $oui.';
        } else if (res.statusCode == 429) {
          _lookupMessage = 'Muitas consultas seguidas. Aguarde um instante.';
        } else {
          _lookupMessage = 'Erro do servidor (${res.statusCode}).';
        }
      });
    } on TimeoutException {
      if (mounted) setState(() => _lookupMessage = 'Tempo esgotado. Verifique a internet.');
    } catch (_) {
      if (mounted) setState(() => _lookupMessage = 'Falha de conexão com a API.');
    } finally {
      if (mounted) setState(() => _lookingUp = false);
    }
  }

  // ===========================================================================
  // UI
  // ===========================================================================
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final width = MediaQuery.sizeOf(context).width;
    final wide = width >= 840; // tablet em paisagem → duas colunas

    final leftColumn = Column(
      children: [
        _buildSignalCard(context),
        const SizedBox(height: 16),
        _buildLookupCard(context),
      ],
    );
    final rightColumn = _buildScanCard(context);

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
            onPressed: () =>
                widget.onToggleTheme(Theme.of(context).brightness),
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
                        Expanded(flex: 5, child: leftColumn),
                        const SizedBox(width: 16),
                        Expanded(flex: 6, child: rightColumn),
                      ],
                    )
                  : Column(children: [
                      leftColumn,
                      const SizedBox(height: 16),
                      rightColumn,
                    ]),
            ),
          ),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Card: Monitor de sinal
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
            Row(
              children: [
                Icon(Icons.wifi_rounded, color: scheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text('Sinal do tablet',
                      style: text.titleMedium
                          ?.copyWith(fontWeight: FontWeight.w600)),
                ),
                if (_ssid != null)
                  Chip(
                    label: Text(_ssid!),
                    avatar: const Icon(Icons.router_rounded, size: 18),
                    visualDensity: VisualDensity.compact,
                  ),
              ],
            ),
            const SizedBox(height: 20),

            // Medidor circular animado
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
                labelStyle: TextStyle(
                    color: quality.color, fontWeight: FontWeight.w700),
              ),

            if (_locationDenied) ...[
              const SizedBox(height: 12),
              _InfoBanner(
                icon: Icons.location_off_rounded,
                text: 'Permita a localização para ler o nome da rede (SSID). '
                    'O Android exige isso para dados Wi-Fi.',
                action: TextButton(
                  onPressed: openAppSettings,
                  child: const Text('Abrir ajustes'),
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
                _StatPill(Icons.speed_rounded, 'Link',
                    _linkSpeed == null || _linkSpeed! <= 0 ? '—' : '$_linkSpeed Mbps'),
                _StatPill(Icons.waves_rounded, 'Banda',
                    _frequency == null || _frequency! <= 0 ? '—' : _bandLabel(_frequency!)),
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
  // Card: Consulta de MAC
  // ---------------------------------------------------------------------------
  Widget _buildLookupCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.fingerprint_rounded, color: scheme.primary),
                const SizedBox(width: 8),
                Text('Fabricante por MAC',
                    style: text.titleMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
              ],
            ),
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

            // Resultado com transição suave
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

  // ---------------------------------------------------------------------------
  // Card: Varredura
  // ---------------------------------------------------------------------------
  Widget _buildScanCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.radar_rounded, color: scheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text('Dispositivos na rede',
                      style: text.titleMedium
                          ?.copyWith(fontWeight: FontWeight.w600)),
                ),
                Badge.count(
                  count: _devices.length,
                  isLabelVisible: _devices.isNotEmpty,
                  backgroundColor: scheme.primary,
                ),
              ],
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: _scanning
                  ? FilledButton.tonalIcon(
                      onPressed: _cancelScan,
                      icon: const Icon(Icons.stop_rounded),
                      label: const Text('Cancelar varredura'),
                      style: FilledButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16)),
                    )
                  : FilledButton.icon(
                      onPressed: _startScan,
                      icon: const Icon(Icons.wifi_find_rounded),
                      label: const Text('Escanear rede'),
                      style: FilledButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16)),
                    ),
            ),
            const SizedBox(height: 16),

            // Barra de progresso linear com porcentagem
            AnimatedSize(
              duration: const Duration(milliseconds: 250),
              child: _scanning
                  ? Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          ClipRRect(
                            borderRadius: BorderRadius.circular(8),
                            child: LinearProgressIndicator(
                              value: _progress,
                              minHeight: 8,
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            'Verificando… ${(_progress * 100).round()}%',
                            style: text.labelMedium
                                ?.copyWith(color: scheme.onSurfaceVariant),
                          ),
                        ],
                      ),
                    )
                  : const SizedBox(width: double.infinity),
            ),

            if (_scanError != null)
              _InfoBanner(
                  icon: Icons.error_outline_rounded, text: _scanError!),

            // Esqueletos pulsantes enquanto nada foi encontrado ainda
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
                      Text('Nenhuma varredura realizada ainda',
                          style: text.bodyMedium
                              ?.copyWith(color: scheme.onSurfaceVariant)),
                    ],
                  ),
                ),
              ),

            // Lista de dispositivos
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: _devices.length,
              separatorBuilder: (_, __) => const SizedBox(height: 10),
              itemBuilder: (_, i) => _DeviceTile(device: _devices[i]),
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

/// Linha de dispositivo, colorida conforme o tipo e a latência.
class _DeviceTile extends StatelessWidget {
  final NetDevice device;
  const _DeviceTile({required this.device});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;

    late final Color bg;
    late final Color fg;
    late final IconData icon;
    late final String label;

    switch (device.kind) {
      case DeviceKind.self:
        bg = scheme.primaryContainer;
        fg = scheme.onPrimaryContainer;
        icon = Icons.tablet_android_rounded;
        label = 'Este tablet';
      case DeviceKind.gateway:
        bg = scheme.tertiaryContainer;
        fg = scheme.onTertiaryContainer;
        icon = Icons.router_rounded;
        label = 'Roteador / Gateway';
      case DeviceKind.other:
        // Cor pela latência: verde (rápido) → âmbar → laranja (lento).
        final base = device.latencyMs < 20
            ? Colors.green
            : (device.latencyMs < 80 ? Colors.amber : Colors.deepOrange);
        bg = base.withValues(alpha: 0.18);
        fg = Theme.of(context).brightness == Brightness.dark
            ? base.shade200
            : base.shade900;
        icon = Icons.devices_rounded;
        label = 'Dispositivo';
    }

    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: 1),
      duration: const Duration(milliseconds: 350),
      curve: Curves.easeOutBack,
      builder: (_, v, child) => Opacity(
        opacity: v.clamp(0, 1),
        child: Transform.translate(
            offset: Offset(0, (1 - v) * 12), child: child),
      ),
      child: Material(
        color: bg,
        borderRadius: BorderRadius.circular(20),
        child: InkWell(
          borderRadius: BorderRadius.circular(20),
          onTap: () {
            Clipboard.setData(ClipboardData(text: device.ip));
            ScaffoldMessenger.of(context)
              ..hideCurrentSnackBar()
              ..showSnackBar(SnackBar(
                content: Text('${device.ip} copiado'),
                behavior: SnackBarBehavior.floating,
                duration: const Duration(seconds: 1),
              ));
          },
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
                      Text(device.ip,
                          style: TextStyle(
                              color: fg,
                              fontSize: 16,
                              fontWeight: FontWeight.w700,
                              fontFeatures: const [
                                FontFeature.tabularFigures()
                              ])),
                      Text(label,
                          style: TextStyle(
                              color: fg.withValues(alpha: 0.75),
                              fontSize: 13)),
                    ],
                  ),
                ),
                if (device.latencyMs > 0)
                  Text('${device.latencyMs} ms',
                      style: TextStyle(
                          color: fg, fontWeight: FontWeight.w600)),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Esqueleto com efeito "shimmer" simples (pulso de opacidade).
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

/// Resultado da consulta: avatar com ícone + nome do fabricante.
class _VendorResult extends StatelessWidget {
  final String vendor;
  const _VendorResult({super.key, required this.vendor});

  /// Mapeia o fabricante para um ícone e uma cor estável (a API não
  /// fornece logotipos, então geramos um emblema consistente).
  IconData _iconFor(String v) {
    final s = v.toLowerCase();
    bool has(List<String> keys) => keys.any(s.contains);
    if (has(['apple'])) return Icons.phone_iphone_rounded;
    if (has(['samsung', 'xiaomi', 'motorola', 'oppo', 'vivo', 'oneplus', 'realme'])) {
      return Icons.smartphone_rounded;
    }
    if (has(['tp-link', 'tplink', 'd-link', 'netgear', 'huawei', 'zte',
        'intelbras', 'ubiquiti', 'mikrotik', 'cisco', 'arris', 'technicolor',
        'aruba', 'asustek router'])) {
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
    if (has(['canon', 'epson', 'brother', 'hp inc', 'xerox'])) {
      return Icons.print_rounded;
    }
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

/// Pílula informativa (IP, gateway, link, banda).
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
              Text(value,
                  style: const TextStyle(fontWeight: FontWeight.w600)),
            ],
          ),
        ],
      ),
    );
  }
}

/// Faixa de aviso/erro reutilizável.
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
