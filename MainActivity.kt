// Caminho: android/app/src/main/kotlin/com/example/netscan_pro/MainActivity.kt
// Se o seu applicationId for outro, ajuste a linha "package" abaixo.
package com.example.netscan_pro

import android.content.Context
import android.net.wifi.WifiManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Ponte nativa para ler o RSSI (dBm), a velocidade do link e a frequência
 * do Wi-Fi atual. Evita depender de plugins de terceiros pouco mantidos.
 */
class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "netscan/wifi")
            .setMethodCallHandler { call, result ->
                if (call.method == "getWifiInfo") {
                    val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                    @Suppress("DEPRECATION")
                    val info = wm.connectionInfo
                    result.success(
                        mapOf(
                            "rssi" to info.rssi,
                            "linkSpeed" to info.linkSpeed,
                            "frequency" to info.frequency
                        )
                    )
                } else {
                    result.notImplemented()
                }
            }
    }
}
