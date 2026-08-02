package ru.qdiver.client

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import mobile.Mobile

/**
 * Всё общение с ядром — здесь.
 *
 * Экраны зовут Core, а не Mobile напрямую: у моста плоские вызовы и строки JSON, а экранам
 * нужны готовые величины. Заодно это единственное место, где приходится помнить, что за
 * `Mobile.geoStatus()` стоит чтение файлов с диска.
 */
object Core {

    /**
     * Каталог баз задаётся один раз при запуске приложения.
     *
     * Раньше это делала только служба VPN, при поднятии туннеля. До первого подключения
     * каталог оставался пустым, ядро падало в домашний каталог — на Android это /sdcard, — и
     * базы не качались вовсе: нет прав. После подключения всё работало, отчего выглядело
     * полной чертовщиной.
     */
    fun init(ctx: Context) {
        Mobile.setGeoDir(ctx.filesDir.absolutePath)
        // Сведения о сети — сюда же. Без этого ядро не запоминает узлы, и после добавления
        // узла в сеть клиент ходил бы по списку из ссылки до самой её перевыдачи.
        Mobile.setStateDir(ctx.filesDir.absolutePath)
    }

    val running: Boolean get() = Mobile.running()

    fun status(): Status = Status.parse(Mobile.status())

    fun network(): NetworkInfo = NetworkInfo.parse(Mobile.network())

    /**
     * Состояние баз.
     *
     * Кешируется намеренно: за вызовом стоит разбор двадцати восьми мегабайт, и звать его на
     * отрисовку строки — то, отчего экран правил открывался две секунды.
     */
    fun geo(fresh: Boolean = false): Geo {
        if (!fresh) geoCache?.let { return it }
        return Geo.parse(Mobile.geoStatus()).also { geoCache = it }
    }

    private var geoCache: Geo? = null

    /** Забыть кеш: базы скачаны или удалены, и прежний ответ больше не верен. */
    fun forgetGeo() {
        geoCache = null
        listsCache.clear()
    }

    /** Скачивает базы. Долгий вызов — только с фонового потока. */
    fun fetchGeo(prefs: Prefs) {
        Mobile.fetchGeo(prefs.bundle, prefs.password)
        forgetGeo()
    }

    /** Что клиент помнит о сети, не спрашивая её. Быстро: чтение одного файла. */
    fun savedNetwork(): SavedNetwork = SavedNetwork.parse(Mobile.networkStatus())

    /**
     * Спрашивает у сети свежий список узлов. Долгий вызов — только с фонового потока.
     *
     * Возвращает причину отказа либо null. Работающему клиенту не нужен: он получает то же
     * самое сам, снапшотом по управляющему каналу.
     */
    fun refreshNetwork(prefs: Prefs): String? = runCatching {
        Mobile.refreshNetwork(prefs.bundle, prefs.password)
        prefs.networkCheckedUnix = System.currentTimeMillis() / 1000
        null
    }.getOrElse { it.message ?: "сеть не ответила" }

    /** Имена списков из баз. Кешируются: их полторы тысячи и меняются они раз в сутки. */
    fun lists(isIP: Boolean): List<String> {
        val key = if (isIP) "ip" else "site"
        listsCache[key]?.let { return it }

        val out = runCatching {
            val arr = JSONArray(Mobile.geoLists(key))
            (0 until arr.length()).map { arr.getString(it) }
        }.getOrDefault(emptyList())
        listsCache[key] = out
        return out
    }

    private val listsCache = mutableMapOf<String, List<String>>()

    /**
     * Создаёт сеть на устройстве: два ключа владельца и подписанный генезис.
     *
     * Долгий вызов — пароль превращается в ключ шифрования дважды, по секунде на ссылку.
     * Бросает исключение с причиной.
     */
    fun createNetwork(name: String, password: String, up: Int, down: Int, mesh: Int): Created =
        Created.parse(Mobile.createNetwork(name, password, up.toLong(), down.toLong(), mesh.toLong()))

    /**
     * Выдаёт обе ссылки владельца — после того, как первый узел в сети.
     *
     * Раньше выдавать нечего: ссылка несёт не только ключ, но и узлы с их адресами, а до
     * включения узла адресов не существует. Ключ без адреса никуда не ведёт.
     *
     * Долгий вызов — шифрование стоит около секунды на ссылку.
     */
    fun issueOwnerBundles(password: String): Created =
        Created.parse(Mobile.issueOwnerBundles(password))

    /** Ключ развёртывания для нового узла. Быстро: чтение журнала и кодировка. */
    fun deployKey(id: String, domain: String, role: String): String =
        Mobile.deployKey(id, domain, role)

    /**
     * Включает поднявшийся узел в сеть: спрашивает его ключ, подписывает запись, отдаёт журнал.
     *
     * code — восемь знаков, напечатанных скриптом развёртывания в терминале. Ими приложение
     * убеждается, что говорит с этим узлом, а не с тем, кто перехватил домен.
     *
     * Долгий вызов — связь с сервером. Бросает исключение, когда узел молчит; несовпадение
     * кода ошибкой не считается и приезжает полем `wrongCode`.
     */
    fun adoptNode(addr: String, role: String, code: String): Adopted =
        Adopted.parse(Mobile.adoptNode(addr, role, code, false))

    /** Держит ли это устройство сеть. Быстро: чтение файла журнала. */
    fun owner(): Owner = Owner.parse(Mobile.ownerStatus())

    /** Принимает ссылку владельца на этом устройстве. */
    fun adoptOwnerBundle(uri: String, password: String) = Mobile.adoptOwnerBundle(uri, password)

    /** Стирает сеть с устройства: журнал, ключ владельца, запомненные узлы. */
    fun wipeOwner() = runCatching { Mobile.wipeOwner() }.getOrNull()

    // ── управление сетью ────────────────────────────────────────────────────────────────
    //
    // Каждая правка — подписанная запись в журнал и сверка с живым узлом. Ошибка «сеть пока о
    // ней не знает» означает, что запись уже сделана, а разнести её не вышло: узел получит её
    // от соседей. Поэтому все методы возвращают причину строкой, а не бросают: экран разводит
    // беду и предупреждение по цвету, а не по наличию.

    fun clients(): List<ClientInfo> = ClientInfo.parseList(Mobile.clients())

    fun nodes(): List<NodeInfo> = NodeInfo.parseList(Mobile.nodes())

    fun networkSettings(): NetSettings = NetSettings.parse(Mobile.networkSettings())

    /** Заводит клиента и отдаёт его ссылку. Долгий вызов: шифрование и связь с узлом. */
    fun addClient(
        id: String,
        label: String,
        limitGB: Int,
        devices: Int,
        days: Int,
        period: String,
        password: String,
    ): String = Mobile.addClient(id, label, limitGB.toLong(), devices.toLong(), days.toLong(), period, password)

    fun reissueClient(id: String, password: String): String = Mobile.reissueClient(id, password)

    fun suspendClient(id: String, on: Boolean): String? = fail { Mobile.suspendClient(id, on) }

    fun revokeClient(id: String): String? = fail { Mobile.revokeClient(id) }

    fun updateNode(id: String, role: String): String? = fail { Mobile.updateNode(id, role) }

    fun revokeNode(id: String): String? = fail { Mobile.revokeNode(id) }

    fun setNetworkSettings(up: Int, down: Int, mesh: Int, dns1: String, dns2: String): String? =
        fail { Mobile.setNetworkSettings(up.toLong(), down.toLong(), mesh.toLong(), dns1, dns2) }

    fun flushDNS(): String? = fail { Mobile.flushDNS() }

    fun syncNetwork(): String? = fail { Mobile.syncNetwork() }

    /** Выполняет действие и отдаёт причину неудачи либо null. */
    private inline fun fail(block: () -> Unit): String? =
        runCatching { block(); null }.getOrElse { it.message ?: "не вышло" }

    /** Применяет правила к работающему клиенту. Возвращает причину отказа либо null. */
    fun applyRules(json: String): String? = runCatching {
        Mobile.setRules(json)
        null
    }.getOrElse { it.message ?: "правила не приняты" }

    /** Переключает умолчание на лету. false означает, что клиент не запущен. */
    fun setViaExit(on: Boolean): Boolean = Mobile.setViaExit(on)

    /**
     * Задаёт потолок отдачи. Ноль означает «как скажет сеть».
     *
     * При работающем клиенте применяется сразу, без переподключения. Отвечает true, если
     * применилось на живой связи.
     */
    fun setBrutalUp(mbps: Int): Boolean =
        Mobile.setBrutalUp(if (mbps > 0) mbps.toLong() else -1L)

    fun setVerbose(on: Boolean) = Mobile.setVerbose(on)
}

/** Состояние клиента: то, что показывает главный экран. */
data class Status(
    val connected: Boolean = false,
    val node: String = "",
    val viaEgress: Boolean = false,
    val network: String = "",
    val sinceUnix: Long = 0,
    val sent: Long = 0,
    val received: Long = 0,
    val usageSent: Long = 0,
    val usageReceived: Long = 0,
    val limitBytes: Long = 0,
    val period: String = "",
    val devices: Int = 0,
    val deviceLimit: Int = 0,
    val rules: Int = 0,
    val nodes: Int = 0,
    val viaExit: Boolean = false,
) {
    val usageTotal: Long get() = usageSent + usageReceived

    /** Доля израсходованного лимита от нуля до единицы. Ноль, когда лимита нет. */
    val limitFraction: Float
        get() = if (limitBytes <= 0) 0f else (usageTotal.toFloat() / limitBytes).coerceAtMost(1f)

    /**
     * Задержка до входного узла.
     *
     * Пока заглушка: кадры ping/pong в управляющем канале объявлены, но измерение не сделано.
     * Место на экране под него занято намеренно — чтобы разметка была настоящей, а не поехала
     * потом, когда число появится.
     */
    fun pingText(): String = "— мс"

    /** Сколько держится связь. Пустая строка, когда связи нет. */
    fun uptime(): String {
        if (!connected || sinceUnix <= 0) return ""
        val secs = System.currentTimeMillis() / 1000 - sinceUnix
        if (secs < 0) return ""
        val h = secs / 3600
        val m = (secs % 3600) / 60
        val s = secs % 60
        return if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%d:%02d".format(m, s)
    }

    companion object {
        fun parse(json: String): Status = runCatching {
            val o = JSONObject(json)
            Status(
                connected = o.optBoolean("connected"),
                node = o.optString("node"),
                viaEgress = o.optBoolean("via_egress"),
                network = o.optString("network"),
                sinceUnix = o.optLong("since_unix"),
                sent = o.optLong("sent"),
                received = o.optLong("received"),
                usageSent = o.optLong("usage_sent"),
                usageReceived = o.optLong("usage_received"),
                limitBytes = o.optLong("limit_bytes"),
                period = o.optString("period"),
                devices = o.optInt("devices"),
                deviceLimit = o.optInt("device_limit"),
                rules = o.optInt("rules"),
                nodes = o.optInt("nodes"),
                viaExit = o.optBoolean("via_exit"),
            )
        }.getOrDefault(Status())
    }
}

/** Что клиент знает о сети. Правил здесь нет: они принадлежат человеку. */
data class NetworkInfo(
    val name: String = "",
    val nodes: List<Node> = emptyList(),
    val hasEgress: Boolean = false,
    val brutalUpMbps: Int = 0,
    val brutalDownMbps: Int = 0,
) {
    data class Node(val id: String, val domain: String, val endpoints: Int)

    companion object {
        fun parse(json: String): NetworkInfo = runCatching {
            val o = JSONObject(json)
            val arr = o.optJSONArray("nodes")
            val nodes = (0 until (arr?.length() ?: 0)).map { i ->
                val n = arr!!.getJSONObject(i)
                Node(
                    id = n.optString("id"),
                    domain = n.optString("domain"),
                    endpoints = n.optJSONArray("endpoints")?.length() ?: 0,
                )
            }
            val s = o.optJSONObject("settings")
            NetworkInfo(
                name = o.optString("name"),
                nodes = nodes,
                hasEgress = o.optBoolean("has_egress"),
                brutalUpMbps = s?.optInt("brutal_up_mbps") ?: 0,
                brutalDownMbps = s?.optInt("brutal_down_mbps") ?: 0,
            )
        }.getOrDefault(NetworkInfo())
    }
}

/**
 * Сеть, запомненная с прошлого раза.
 *
 * Пустое имя означает, что сеть ещё не рассказывала о себе: клиент пойдёт по узлам из ссылки.
 */
data class SavedNetwork(
    val network: String = "",
    val nodes: Int = 0,
    val egress: Boolean = false,
    val changed: Boolean = false,
    val savedUnix: Long = 0,
) {
    val known: Boolean get() = network.isNotEmpty()

    companion object {
        fun parse(json: String): SavedNetwork = runCatching {
            val o = JSONObject(json)
            SavedNetwork(
                network = o.optString("network"),
                nodes = o.optInt("nodes"),
                egress = o.optBoolean("egress"),
                changed = o.optBoolean("changed"),
                savedUnix = o.optLong("saved_unix"),
            )
        }.getOrDefault(SavedNetwork())
    }
}

/** Только что созданная сеть: отпечаток и обе ссылки владельца. */
data class Created(
    val genesis: String = "",
    val network: String = "",
    val working: String = "",
    val spare: String = "",
) {
    companion object {
        fun parse(json: String): Created = runCatching {
            val o = JSONObject(json)
            Created(
                genesis = o.optString("genesis"),
                network = o.optString("network"),
                working = o.optString("working"),
                spare = o.optString("spare"),
            )
        }.getOrDefault(Created())
    }
}

/**
 * Чем кончилась попытка включить узел.
 *
 * `wrongCode` — не сбой связи, а ответ: на том конце не тот узел. Повторять после него нельзя,
 * ключ у узла один и следующая попытка даст то же самое.
 */
data class Adopted(
    val adopted: Boolean = false,
    val wrongCode: Boolean = false,
    val id: String = "",
    val domain: String = "",
) {
    companion object {
        fun parse(json: String): Adopted = runCatching {
            val o = JSONObject(json)
            Adopted(
                adopted = o.optBoolean("adopted"),
                wrongCode = o.optBoolean("wrong_code"),
                id = o.optString("id"),
                domain = o.optString("domain"),
            )
        }.getOrDefault(Adopted())
    }
}

/** Держит ли это устройство сеть — и что в её журнале. */
data class Owner(
    val owner: Boolean = false,
    val network: String = "",
    val genesis: String = "",
    val nodes: Int = 0,
    val records: Int = 0,
) {
    companion object {
        fun parse(json: String): Owner = runCatching {
            val o = JSONObject(json)
            Owner(
                owner = o.optBoolean("owner"),
                network = o.optString("network"),
                genesis = o.optString("genesis"),
                nodes = o.optInt("nodes"),
                records = o.optInt("records"),
            )
        }.getOrDefault(Owner())
    }
}

/** Клиент сети, каким его видит владелец. */
data class ClientInfo(
    val id: String,
    val label: String = "",
    val suspended: Boolean = false,
    val limitBytes: Long = 0,
    val period: String = "",
    val devices: Int = 0,
    val expiresUnix: Long = 0,
) {
    /** Строка под именем: лимиты и срок, человеческим языком. */
    fun describe(): String {
        val parts = mutableListOf<String>()
        parts += if (limitBytes > 0) {
            bytes(limitBytes) + if (period.isEmpty()) "" else " / ${periodName(period)}"
        } else "без потолка"
        if (devices > 0) parts += "устройств $devices"
        if (expiresUnix > 0) {
            val left = expiresUnix - System.currentTimeMillis() / 1000
            parts += if (left > 0) "ещё ${left / 86400} дн" else "срок вышел"
        }
        return parts.joinToString(" · ")
    }

    companion object {
        fun parseList(json: String): List<ClientInfo> = runCatching {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ClientInfo(
                    id = o.optString("id"),
                    label = o.optString("label"),
                    suspended = o.optBoolean("suspended"),
                    limitBytes = o.optLong("limit_bytes"),
                    period = o.optString("period"),
                    devices = o.optInt("devices"),
                    expiresUnix = o.optLong("expires_unix"),
                )
            }
        }.getOrDefault(emptyList())

        private fun periodName(p: String) = when (p) {
            "daily" -> "сутки"
            "weekly" -> "неделя"
            "monthly" -> "месяц"
            else -> p
        }
    }
}

/** Узел сети, каким его видит владелец. Выходные здесь есть — это его экран, а не клиента. */
data class NodeInfo(
    val id: String,
    val domain: String = "",
    val roles: List<String> = emptyList(),
    val endpoints: List<String> = emptyList(),
) {
    companion object {
        fun parseList(json: String): List<NodeInfo> = runCatching {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                NodeInfo(
                    id = o.optString("id"),
                    domain = o.optString("domain"),
                    roles = o.optJSONArray("roles").toList(),
                    endpoints = o.optJSONArray("endpoints").toList(),
                )
            }
        }.getOrDefault(emptyList())
    }
}

/** Параметры сети: потолки и резолверы. */
data class NetSettings(
    val up: Int = 0,
    val down: Int = 0,
    val mesh: Int = 0,
    val dnsPrimary: String = "",
    val dnsSecondary: String = "",
) {
    companion object {
        fun parse(json: String): NetSettings = runCatching {
            val o = JSONObject(json)
            NetSettings(
                up = o.optInt("brutal_up_mbps"),
                down = o.optInt("brutal_down_mbps"),
                mesh = o.optInt("brutal_mesh_mbps"),
                dnsPrimary = o.optString("dns_primary"),
                dnsSecondary = o.optString("dns_secondary"),
            )
        }.getOrDefault(NetSettings())
    }
}

private fun JSONArray?.toList(): List<String> =
    if (this == null) emptyList() else (0 until length()).map { optString(it) }

/** Состояние баз geosite и geoip. */
data class Geo(
    val installed: String = "",
    val latest: String = "",
    val sites: Int = 0,
    val ips: Int = 0,
) {
    val missing: Boolean get() = installed.isEmpty()

    companion object {
        fun parse(json: String): Geo = runCatching {
            val o = JSONObject(json)
            Geo(
                installed = o.optString("installed"),
                latest = o.optString("latest"),
                sites = o.optInt("sites"),
                ips = o.optInt("ips"),
            )
        }.getOrDefault(Geo())
    }
}

/** Человеческий объём: байты в килобайты, мегабайты и так далее. */
fun bytes(b: Long): String {
    if (b < 1024) return "$b Б"
    val units = listOf("КБ", "МБ", "ГБ", "ТБ")
    var v = b.toDouble()
    var i = -1
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024
        i++
    }
    return if (v >= 100) "%.0f %s".format(v, units[i]) else "%.1f %s".format(v, units[i])
}

fun speed(bps: Long): String = bytes(bps) + "/с"

/** Сколько времени прошло, словами. Точная дата человеку здесь не нужна. */
fun ago(unix: Long): String {
    if (unix <= 0) return "никогда"
    val secs = System.currentTimeMillis() / 1000 - unix
    return when {
        secs < 0 -> "только что"
        secs < 3600 -> "${secs / 60} мин назад"
        secs < 86400 -> "${secs / 3600} ч назад"
        else -> "${secs / 86400} дн назад"
    }
}
