package ru.qdiver.client

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import mobile.Logger
import mobile.Mobile

/**
 * Служба туннеля.
 *
 * Интерфейс создаёт система по нашему запросу — приложение прав на это не имеет и иметь не
 * должно. Нам достаётся открытый дескриптор, который уходит в ядро на Go; адреса, маршруты и
 * службу имён система расставляет по тому, что мы у неё попросили здесь.
 *
 * Своё соединение с узлом выводится из туннеля целиком: addDisallowedApplication на самих
 * себя. Иначе связь с входным узлом ушла бы в туннель, который сам через неё и работает.
 */
class QdVpnService : VpnService(), Logger {

    /**
     * Работает ли туннель.
     *
     * Дескриптор здесь не хранится намеренно: он отдан ядру целиком, и владелец у него ровно
     * один — см. startTunnel.
     *
     * Атомарный, потому что остановка приходит с двух сторон сразу: команда снимает туннель в
     * своём потоке и зовёт stopSelf, а система в ответ вызывает onDestroy на главном. Кто
     * дошёл первым — тот и останавливает, второй молчит.
     */
    private val running = AtomicBoolean()

    /**
     * onStartCommand принимает три разных обращения, и путать их нельзя.
     *
     * Команда «остановить» — от человека, тут всё очевидно.
     *
     * Пустое намерение — это система: она убила процесс (очистка недавних, нехватка памяти) и
     * подняла службу заново, потому что мы вернули START_STICKY. Раньше на этом месте туннель
     * глушился, и очистка списка недавних рвала связь наглухо. Теперь он поднимается заново из
     * сохранённых настроек — ради этого START_STICKY и возвращается.
     *
     * Оттуда же приходит always-on: включив его в настройках системы, человек получает запуск
     * службы без единого касания приложения, и намерение при этом тоже пустое.
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopInBackground()
            return START_NOT_STICKY
        }

        val prefs = Prefs(this)
        if (intent == null) {
            if (!prefs.configured) {
                // Сети нет — восстанавливать нечего. Молча уходим, иначе система будет
                // поднимать нас снова и снова.
                stopSelf()
                return START_NOT_STICKY
            }
            Journal.post("туннель восстанавливается: службу перезапустила система")
        }

        runCatching { startTunnel(prefs) }.onFailure { e ->
            Log.e(TAG, "туннель не поднялся", e)
            Journal.post("туннель не поднялся: ${e.message}")
            stopInBackground()
        }
        return START_STICKY
    }

    private fun startTunnel(prefs: Prefs) {
        if (running.get()) return
        check(prefs.bundle.isNotEmpty()) { "сеть не задана" }

        val builder = Builder()
            .setSession("QUIC Diver")
            .setMtu(MTU)
            .addAddress(ADDRESS, PREFIX)
            // Весь трафик в туннель. Две половинки вместо 0.0.0.0/0 здесь не нужны:
            // маршрутами занимается система, и спорить с прежним маршрутом не приходится.
            .addRoute("0.0.0.0", 0)
            .addDnsServer(DNS)

        // Пока ядро не готово — идёт гонка входных узлов, рвётся связь, переключается сеть —
        // система придержит пакеты вместо того, чтобы выпустить их наружу в обход туннеля.
        builder.setBlocking(true)

        // Себя — мимо туннеля. Иначе соединение с входным узлом ушло бы в туннель, который
        // сам через это соединение и работает.
        builder.addDisallowedApplication(packageName)

        val iface = builder.establish()
            ?: error("система не дала интерфейс: разрешение отозвано?")

        startForeground(NOTIFICATION_ID, notification("подключаюсь"))

        // Дескриптор отдаётся ядру целиком: detachFd снимает владение с ParcelFileDescriptor,
        // и закрывать его будет только Go.
        //
        // Иначе выходит двойное закрытие: ядро закрывает свой файл при остановке, а следом
        // ParcelFileDescriptor закрывает тот же номер второй раз. Android такое не прощает —
        // fdsan убивает процесс целиком, и приложение просто исчезает с экрана.
        val fd = iface.detachFd()
        try {
            Mobile.setLogger(this)
            // Настройки уходят до запуска: ядро читает их, когда собирает себя.
            Core.init(this)
            Mobile.setDeviceID(androidID())
            Mobile.setVerbose(prefs.verbose)
            Mobile.setKeepDNS(prefs.keepDNS)
            Mobile.setRules(prefs.rules)
            Mobile.setGeoMode(if (prefs.geoAuto) "auto" else "off")
            // Ноль на экране означает «как скажет сеть», в языке ядра это минус единица.
            Mobile.setBrutalUp(if (prefs.brutalUp > 0) prefs.brutalUp.toLong() else -1L)
            Mobile.start(fd.toLong(), prefs.bundle, prefs.password, prefs.viaExit, MTU.toLong())
        } catch (e: Exception) {
            // Ядро не взяло дескриптор — закрываем сами, иначе он утечёт до конца жизни
            // процесса.
            ParcelFileDescriptor.adoptFd(fd).close()
            throw e
        }

        running.set(true)
        Journal.post("туннель поднят, ядро ${Mobile.version()}")
    }

    /**
     * Устойчивое имя устройства.
     *
     * ANDROID_ID переживает перезагрузки и обновления приложения, но сбрасывается при сбросе к
     * заводским настройкам и различается для разных приложений — то есть узнать по нему
     * устройство где-то ещё нельзя. Ровно это и нужно: отличать устройства друг от друга, не
     * раздавая общесистемных идентификаторов.
     */
    @SuppressLint("HardwareIds")
    private fun androidID(): String =
        Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: ""

    /**
     * Останавливает ядро не на главном потоке.
     *
     * Mobile.stop ждёт, пока ядро действительно закончит: отдать дескриптор системе раньше
     * этого нельзя. Ожидание на главном потоке — прямой путь к «приложение не отвечает».
     */
    private fun stopInBackground() {
        Thread({ stopTunnel() }, "qdiver-stop").start()
    }

    private fun stopTunnel() {
        // Снимаем ровно один раз. Команда на остановку зовёт stopSelf, система в ответ зовёт
        // onDestroy, и без этой проверки человек видел бы «туннель снят» дважды.
        if (!running.compareAndSet(true, false)) return

        runCatching { Mobile.stop() }.onFailure { Log.w(TAG, "остановка ядра", it) }
        Journal.post("туннель снят")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        // Здесь уже без потока: система ждёт возврата, и уходить, оставив ядро работать,
        // нельзя — оно держит дескриптор, который система вот-вот отберёт.
        stopTunnel()
        super.onDestroy()
    }

    /** onRevoke зовётся, когда человек отобрал разрешение или включил другой VPN. */
    override fun onRevoke() {
        Journal.post("разрешение отозвано системой")
        stopInBackground()
        super.onRevoke()
    }

    /** log принимает строки журнала от ядра. Реализует mobile.Logger. */
    override fun log(line: String) {
        Log.i(TAG, line)
        Journal.post(line)
    }

    private fun notification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Туннель", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Состояние туннеля QUIC Diver"
            }
        )

        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("QUIC Diver")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START = "ru.qdiver.client.START"
        const val ACTION_STOP = "ru.qdiver.client.STOP"
        const val EXTRA_BUNDLE = "bundle"
        const val EXTRA_PASSWORD = "password"

        private const val TAG = "qdiver"
        private const val CHANNEL = "qdiver-tunnel"
        private const val NOTIFICATION_ID = 1

        /** Адрес интерфейса и маска. Совпадает с умолчанием ядра. */
        private const val ADDRESS = "10.7.0.2"
        private const val PREFIX = 24

        /**
         * Резолвер внутри туннеля.
         *
         * Второй адрес подменного диапазона — там ядро поднимает свою службу имён. Адрес
         * самого интерфейса для этого не годится: система считает его своим и до нашего стека
         * пакеты не доводит.
         */
        private const val DNS = "198.18.0.1"

        private const val MTU = 1400
    }
}
