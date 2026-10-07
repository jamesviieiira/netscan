// Caminho: android/app/src/main/kotlin/com/example/netscan_pro/MainActivity.kt
// Se o seu applicationId for outro, ajuste a linha "package" abaixo.
package com.example.netscan_pro

import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import android.bluetooth.le.ScanResult as BleResult

/**
 * Ponte nativa usada pelo app Flutter:
 *  - getWifiInfo : RSSI, velocidade e frequência do Wi-Fi atual
 *  - scanWifi    : lista de redes Wi-Fi próximas
 *  - scanBle     : dispositivos Bluetooth Low Energy próximos (~8 s)
 *  - multicast   : liga/desliga o MulticastLock (necessário para mDNS/SSDP)
 */
class MainActivity : FlutterActivity() {

    private val handler = Handler(Looper.getMainLooper())
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "netscan/wifi")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getWifiInfo" -> getWifiInfo(result)
                    "scanWifi" -> scanWifi(result)
                    "scanBle" -> scanBle(result)
                    "multicast" -> setMulticast(call.arguments as? Boolean ?: false, result)
                    else -> result.notImplemented()
                }
            }
    }

    // ---------------------------------------------------------------- Wi-Fi atual
    private fun getWifiInfo(result: MethodChannel.Result) {
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
    }

    // ---------------------------------------------------------------- Redes próximas
    private fun scanWifi(result: MethodChannel.Result) {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        var done = false
        var receiverRef: BroadcastReceiver? = null

        fun finish() {
            if (done) return
            done = true
            receiverRef?.let {
                try {
                    applicationContext.unregisterReceiver(it)
                } catch (_: Exception) {
                }
            }
            try {
                val list = wm.scanResults.map { r ->
                    mapOf(
                        "ssid" to (r.SSID ?: ""),
                        "bssid" to (r.BSSID ?: ""),
                        "level" to r.level,
                        "frequency" to r.frequency,
                        "capabilities" to (r.capabilities ?: "")
                    )
                }
                result.success(list)
            } catch (e: SecurityException) {
                result.error("permission", "Permissão de localização necessária.", null)
            }
        }

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                finish()
            }
        }
        receiverRef = receiver
        applicationContext.registerReceiver(
            receiver,
            IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        )

        @Suppress("DEPRECATION")
        val started = try {
            wm.startScan()
        } catch (e: Exception) {
            false
        }
        // O Android limita a frequência das varreduras: se não iniciou,
        // devolve rapidamente o último resultado em cache.
        handler.postDelayed({ finish() }, if (started) 6000L else 300L)
    }

    // ---------------------------------------------------------------- Bluetooth LE
    private fun scanBle(result: MethodChannel.Result) {
        val bm = getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bm?.adapter
        if (adapter == null || !adapter.isEnabled) {
            result.error("bt_off", "Bluetooth desligado ou indisponível. Ligue-o e tente de novo.", null)
            return
        }
        val scanner = adapter.bluetoothLeScanner
        if (scanner == null) {
            result.error("bt_off", "Bluetooth indisponível.", null)
            return
        }

        val found = HashMap<String, MutableMap<String, Any?>>()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, r: BleResult) {
                val addr = r.device.address ?: return
                val rec = r.scanRecord

                val name: String = try {
                    rec?.deviceName ?: r.device.name ?: ""
                } catch (e: SecurityException) {
                    rec?.deviceName ?: ""
                }

                val entry = found[addr] ?: mutableMapOf<String, Any?>(
                    "address" to addr,
                    "name" to "",
                    "rssi" to -127,
                    "mfr" to ArrayList<Int>(),
                    "uuids" to ArrayList<String>()
                )

                if (name.isNotBlank()) entry["name"] = name
                if (r.rssi > (entry["rssi"] as Int)) entry["rssi"] = r.rssi

                @Suppress("UNCHECKED_CAST")
                val mfrList = entry["mfr"] as ArrayList<Int>
                val sd = rec?.manufacturerSpecificData
                if (sd != null) {
                    for (i in 0 until sd.size()) {
                        val id = sd.keyAt(i)
                        if (!mfrList.contains(id)) mfrList.add(id)
                    }
                }

                @Suppress("UNCHECKED_CAST")
                val uuidList = entry["uuids"] as ArrayList<String>
                rec?.serviceUuids?.forEach {
                    val s = it.toString()
                    if (!uuidList.contains(s)) uuidList.add(s)
                }

                found[addr] = entry
            }
        }

        try {
            scanner.startScan(
                null,
                ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                callback
            )
        } catch (e: SecurityException) {
            result.error("permission", "Permissão de Bluetooth/localização necessária.", null)
            return
        } catch (e: Exception) {
            result.error("scan_failed", "Não foi possível iniciar a busca Bluetooth.", null)
            return
        }

        handler.postDelayed({
            try {
                scanner.stopScan(callback)
            } catch (_: Exception) {
            }
            result.success(found.values.toList())
        }, 8000L)
    }

    // ---------------------------------------------------------------- Multicast
    private fun setMulticast(enable: Boolean, result: MethodChannel.Result) {
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            if (enable) {
                if (multicastLock == null) {
                    multicastLock = wm.createMulticastLock("netscan").apply {
                        setReferenceCounted(false)
                    }
                }
                multicastLock?.acquire()
            } else {
                multicastLock?.let { if (it.isHeld) it.release() }
            }
            result.success(true)
        } catch (e: Exception) {
            result.success(false)
        }
    }
}
