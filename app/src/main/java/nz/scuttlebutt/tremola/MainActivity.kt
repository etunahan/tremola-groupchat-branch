package nz.scuttlebutt.tremola

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.net.*
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Handler
import android.text.format.Formatter
import android.util.Log
import android.view.Window
import android.webkit.WebView
import android.webkit.WebViewClient
import com.google.zxing.integration.android.IntentIntegrator
import nz.scuttlebutt.tremola.ssb.TremolaState
import nz.scuttlebutt.tremola.ssb.peering.RpcResponder
import nz.scuttlebutt.tremola.ssb.peering.RpcServices
import nz.scuttlebutt.tremola.ssb.peering.UDPbroadcast
import nz.scuttlebutt.tremola.utils.Constants
import java.lang.Thread.sleep
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var tremolaState: TremolaState
    var broadcast_socket: DatagramSocket? = null
    var server_socket: ServerSocket? = null
    var udp: UDPbroadcast? = null
    val networkRequest = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        .build()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setRequestedOrientation (ActivityInfo.SCREEN_ORIENTATION_PORTRAIT)
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.activity_main)
        tremolaState = TremolaState(this)

        //Testing / Debugging
        /**
        val gmTest = GroupMessagesTest(tremolaState.idStore.identity)
        gmTest.encryptDecryptTest()
        gmTest.deriveSecretTest()
        gmTest.slotTest()
        gmTest.unslotTest()
        gmTest.boxTest()
        gmTest.box2Test()
        gmTest.unboxTest()
        gmTest.cloakedMsgIdTest()
        */

        mkSockets()

        Log.d("IDENTITY", "is ${tremolaState.idStore.identity.toRef()}")

        val webView = findViewById<WebView>(R.id.webView)
        tremolaState.wai = WebAppInterface(this, tremolaState, webView)

        webView.setBackgroundColor(0) // Color.parseColor("#FFffa0a0"))
        webView.webViewClient = WebViewClient()
        webView.addJavascriptInterface(tremolaState.wai, "Android")
        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.loadUrl("file:///android_asset/web/tremola.html")
        // webSettings?.javaScriptCanOpenWindowsAutomatically = true

        // react on connectivity changes:
        if (networkCallback == null) {
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) {
                    Log.d("onLost", "${network}")
                    super.onLost(network)
                    /*
                    try { broadcast_socket?.close() } catch (e: Exception) {}
                    broadcast_socket = null
                    try { server_socket?.close() } catch (e: Exception) {}
                    server_socket = null
                    */
                }
                override fun onLinkPropertiesChanged(nw: Network, prop: LinkProperties) {
                    Log.d("onLinkPropertiesChanged", "${nw} ${prop}")
                    super.onLinkPropertiesChanged(nw, prop)
                    /*
                    server_socket?.let {
                        if (it.inetAddress in prop.linkAddresses) {
                            Log.d("onLinkPropertiesChanged", "no need for new sock")
                            return
                        }
                    }
                    */
                    mkSockets()
                }
                /*
                override fun onAvailable(network: Network) {
                    Log.d("onAvailable", "${network}")
                    super.onAvailable(network)
                }
                */
            }
        }
        udp = UDPbroadcast(this, tremolaState.wai)
        val lck = ReentrantLock()

        val t0 = thread(isDaemon=true) {
            try {
                udp!!.beacon(tremolaState.idStore.identity.verifyKey, lck, Constants.SSB_IPV4_TCPPORT)
            } catch (e: Exception) {
                Log.d("beacon thread", "died ${e}")
            }
        }

        val t1 = thread(isDaemon=true) {
            val wifi = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager
            val mLock = wifi.createMulticastLock("lock")
            mLock.acquire()
            try {
                udp!!.listen(lck)
            } catch (e: Exception) {
                Log.d("listen thread", "died ${e}")
            }
        }
        val t2 = thread(isDaemon=true)  { // accept loop, robust against reassigned server_socket
             while (true) {
                 var socket: Socket?
                 try {
                     socket = server_socket!!.accept()
                 } catch (e: Exception) {
                     sleep(3000)
                     continue
                 }
                 thread() { // one thread per connection
                     val rpcStream = RpcResponder(tremolaState, socket,
                         Constants.SSB_NETWORKIDENTIFIER)
                     rpcStream.defineServices(RpcServices(tremolaState))
                     rpcStream.startStreaming()
                 }
            }
        }
        t0.priority = 10
        t1.priority = 10

        t2.priority = 6
        Log.d("Thread priorities", "${t0.priority} ${t1.priority} ${t2.priority}")
    }

    override fun onBackPressed() {
        tremolaState.wai.eval("onBackPressed();")
    }

    fun _onBackPressed() {
        Handler(this.getMainLooper()).post {
            super.onBackPressed()
        }
    }

    // pt 3 in https://betterprogramming.pub/5-android-webview-secrets-you-probably-didnt-know-b23f8a8b5a0c

    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            Log.d("activityResult", result.toString())
            val cmd: String
            if (result.contents == null) {
                cmd = "qr_scan_failure();"
            } else {
                cmd = "qr_scan_success('" + result.contents + "');"
            }
            tremolaState.wai.eval(cmd)
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onResume() {
        Log.d("onResume", "")
        super.onResume()
        try {
            (getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager)
                .registerNetworkCallback(networkRequest, networkCallback!!)
        } catch (e: Exception) {}
    }

    override fun onPause() {
        Log.d("onPause", "")
        super.onPause()
        try {
            (getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager)
                .unregisterNetworkCallback(networkCallback!!)
        } catch (e: Exception) {}
    }

    fun onSaveInstanceState() {
        Log.d("onSaveInstanceState", "")
    }
    override fun onStop() {
        Log.d("onStop", "")
        super.onStop()
    }
    override fun onDestroy() {
        Log.d("onDestroy", "")
        try { broadcast_socket?.close() } catch (e: Exception) {}
        broadcast_socket = null
        super.onDestroy()
    }

    private fun mkSockets() {
        try { broadcast_socket?.close() } catch (e: Exception) {}
        broadcast_socket = DatagramSocket(
            Constants.SSB_IPV4_UDPPORT, // where to listen
            InetAddress.getByName("0.0.0.0")
        )
        broadcast_socket?.broadcast = true
        Log.d("new bcast sock", "${broadcast_socket}, UDP port ${broadcast_socket?.localPort}")
        val wifiManager = getSystemService(Context.WIFI_SERVICE) as WifiManager
        try { server_socket?.close() } catch (e: Exception) {}
        server_socket =  ServerSocket(Constants.SSB_IPV4_TCPPORT)
        Log.d("SERVER TCP addr", "${Formatter.formatIpAddress(wifiManager.connectionInfo.ipAddress)}:${server_socket!!.localPort}")
    }
}