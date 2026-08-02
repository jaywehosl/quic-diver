package ru.qdiver.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.view.WindowCompat

/** Куда смотрит человек прямо сейчас. */
enum class Screen { SETUP, CREATE, MAIN }

class MainActivity : ComponentActivity() {

    private lateinit var prefs: Prefs
    private var screen by mutableStateOf(Screen.MAIN)
    private var pendingConnect = false

    /**
     * Разрешение на VPN система спрашивает сама и только один раз на установку. Пока его нет,
     * интерфейс нам не дадут, и запускать службу бессмысленно.
     */
    private val askVpn = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == Activity.RESULT_OK && pendingConnect) {
            startTunnel()
        }
        pendingConnect = false
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Приложение рисует себя под системными панелями: иначе строка состояния остаётся
        // системной прозрачной, а полоса жестов — глухо белой или чёрной, и обе не имеют
        // отношения к тому, что под ними.
        enableEdgeToEdge()
        prefs = Prefs(this)
        Core.init(this)

        takeBundle(intent)
        screen = if (prefs.configured) Screen.MAIN else Screen.SETUP

        setContent {
            val dark = isSystemInDarkTheme()
            SideEffect {
                // Значки в панелях перекрашиваются под наш фон: тёмные на светлом, светлые на
                // тёмном. Без этого в тёмной теме часы и батарея исчезают.
                WindowCompat.getInsetsController(window, window.decorView).apply {
                    isAppearanceLightStatusBars = !dark
                    isAppearanceLightNavigationBars = !dark
                }
                // Система сама подкладывает под полосу жестов полупрозрачную плашку, чтобы
                // жест был виден на любом фоне. Наш фон и так ровный, а плашка выглядит
                // чужой полосой снизу — отказываемся.
                window.isNavigationBarContrastEnforced = false
            }

            MaterialTheme(colorScheme = qdiverColors(dark)) {
                // Surface красит весь экран, включая полосы под панелями: иначе там остаётся
                // фон окна из темы, и в тёмной теме строка состояния выходит белой.
                //
                // Отступы — уже на содержимом, внутри: у выреза, полосы жестов и клавиатуры
                // высота разная на каждом устройстве, и угадывать её нельзя.
                Surface(modifier = Modifier.fillMaxSize()) {
                    Box(Modifier.windowInsetsPadding(WindowInsets.systemBars)) {
                        App()
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (takeBundle(intent)) {
            screen = Screen.MAIN
        }
    }

    @Composable
    private fun App() {
        val log = remember { Journal }

        // Из создания сети «назад» ведёт на первый экран, а не на главный: главного ещё нет —
        // сети нет тоже. Внутри Shell «назад» обрабатывается им самим.
        BackHandler(enabled = screen == Screen.CREATE) { screen = Screen.SETUP }

        when (screen) {
            Screen.SETUP -> SetupScreen(
                prefs = prefs,
                onDone = { screen = Screen.MAIN },
                onCreate = { screen = Screen.CREATE },
            )
            Screen.CREATE -> CreateNetworkScreen(
                prefs = prefs,
                onBack = { screen = Screen.SETUP },
                onDone = { screen = Screen.MAIN },
            )
            // Дальше экранов нет — есть одна раскладка со свайпами во все стороны (Shell).
            else -> Shell(
                prefs = prefs,
                journal = log,
                onConnect = ::connect,
                onDisconnect = ::disconnect,
                onWiped = { screen = Screen.SETUP },
            )
        }
    }

    /** takeBundle забирает ссылку из намерения: из нажатой qdiver:// или из поля при adb. */
    private fun takeBundle(intent: Intent?): Boolean {
        if (intent == null) return false

        val bundle = when {
            intent.data?.scheme == "qdiver" -> intent.dataString
            else -> intent.getStringExtra(QdVpnService.EXTRA_BUNDLE)
        }
        if (bundle.isNullOrEmpty()) return false

        prefs.setNetwork(bundle, intent.getStringExtra(QdVpnService.EXTRA_PASSWORD) ?: prefs.password)
        Journal.post("ссылка на сеть принята")
        return true
    }

    private fun connect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingConnect = true
            askVpn.launch(consent)
            return
        }
        startTunnel()
    }

    private fun startTunnel() {
        startForegroundService(
            Intent(this, QdVpnService::class.java).setAction(QdVpnService.ACTION_START)
        )
    }

    private fun disconnect() {
        startService(Intent(this, QdVpnService::class.java).setAction(QdVpnService.ACTION_STOP))
    }
}
