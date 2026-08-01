package ru.qdiver.client

import android.content.Context

/**
 * Настройки приложения.
 *
 * Читают их трое: экраны их правят, служба берёт при запуске ядра, главный экран решает по
 * ним, есть ли что запускать. Три копии имён ключей в трёх местах разошлись бы на первой же
 * правке.
 *
 * Всё, что здесь лежит, — выбор человека, а не состояние сети. Состояние спрашивается у ядра и
 * не хранится нигде: пережившая перезапуск копия «подключено» врала бы.
 */
class Prefs(ctx: Context) {

    private val p = ctx.applicationContext.getSharedPreferences("qdiver", Context.MODE_PRIVATE)

    var bundle: String
        get() = p.getString(KEY_BUNDLE, "") ?: ""
        set(value) = p.edit().putString(KEY_BUNDLE, value).apply()

    var password: String
        get() = p.getString(KEY_PASSWORD, "") ?: ""
        set(value) = p.edit().putString(KEY_PASSWORD, value).apply()

    var viaExit: Boolean
        get() = p.getBoolean(KEY_VIA_EXIT, true)
        set(value) = p.edit().putBoolean(KEY_VIA_EXIT, value).apply()

    /** Правила маршрутизации — массив JSON. Пустая строка означает, что правил нет. */
    var rules: String
        get() = p.getString(KEY_RULES, "") ?: ""
        set(value) = p.edit().putString(KEY_RULES, value).apply()

    /**
     * Потолок отдачи для BRUTAL, Мбит/с. Ноль означает «взять из сети».
     *
     * Ноль, а не отрицательное: человеку в поле проще стереть число, чем вписать минус
     * единицу. В язык ядра это переводится при запуске.
     */
    var brutalUp: Int
        get() = p.getInt(KEY_BRUTAL_UP, 0)
        set(value) = p.edit().putInt(KEY_BRUTAL_UP, maxOf(value, 0)).apply()

    /** Как часто сверяться со свежестью баз, в днях. */
    var geoDays: Int
        get() = p.getInt(KEY_GEO_DAYS, 7)
        set(value) = p.edit().putInt(KEY_GEO_DAYS, value).apply()

    /**
     * Качать ли обновление баз само.
     *
     * Выключено — клиент только проверит и скажет, что вышло свежее. По умолчанию так: базы
     * весят под тридцать мегабайт, и уносить их из сотового трафика без спроса нельзя.
     */
    var geoAuto: Boolean
        get() = p.getBoolean(KEY_GEO_AUTO, false)
        set(value) = p.edit().putBoolean(KEY_GEO_AUTO, value).apply()

    /**
     * Перехватывать ли шифрованный DNS.
     *
     * По умолчанию включено: браузер со своим DoH разрешает имена мимо туннеля, и правила по
     * доменам перестают работать целиком — молча, без единой строки в журнале. Выключать это
     * стоит, только если понимаешь, что теряешь.
     */
    var keepDNS: Boolean
        get() = p.getBoolean(KEY_KEEP_DNS, true)
        set(value) = p.edit().putBoolean(KEY_KEEP_DNS, value).apply()

    /**
     * Как часто спрашивать у сети список узлов, в часах. От 1 до 24 (решение 007 §4).
     *
     * Пока клиент работает, интервал ни при чём: сеть присылает сведения сама, на каждое
     * изменение журнала. Он нужен для другого — клиент выключен неделю, за это время узел
     * сменил адрес, и человек об этом узнаёт ровно в момент, когда ничего не подключается.
     */
    var networkHours: Int
        get() = p.getInt(KEY_NETWORK_HOURS, 12)
        set(value) = p.edit().putInt(KEY_NETWORK_HOURS, value.coerceIn(1, 24)).apply()

    /**
     * Что делать, когда интервал вышел: "auto", "ask", "off".
     *
     * По умолчанию auto: сведения весят килобайты, и спрашивать разрешения на их обновление
     * так же странно, как спрашивать разрешения открыть соединение с узлом.
     */
    var networkMode: String
        get() = p.getString(KEY_NETWORK_MODE, MODE_AUTO) ?: MODE_AUTO
        set(value) = p.edit().putString(KEY_NETWORK_MODE, value).apply()

    /** Когда в последний раз спрашивали сеть, в секундах эпохи. */
    var networkCheckedUnix: Long
        get() = p.getLong(KEY_NETWORK_CHECKED, 0)
        set(value) = p.edit().putLong(KEY_NETWORK_CHECKED, value).apply()

    /** Пора ли спрашивать сеть: интервал вышел и режим это позволяет. */
    fun networkDue(nowUnix: Long = System.currentTimeMillis() / 1000): Boolean {
        if (networkMode == MODE_OFF) return false
        return nowUnix - networkCheckedUnix >= networkHours * 3600L
    }

    /** Подробный журнал: строка на каждый поток. Нужен, когда что-то ведёт себя непонятно. */
    var verbose: Boolean
        get() = p.getBoolean(KEY_VERBOSE, false)
        set(value) = p.edit().putBoolean(KEY_VERBOSE, value).apply()

    /** Есть ли сеть: без ссылки приложению нечего показывать и нечего настраивать. */
    val configured: Boolean get() = bundle.isNotEmpty()

    fun setNetwork(bundle: String, password: String) {
        p.edit().putString(KEY_BUNDLE, bundle).putString(KEY_PASSWORD, password).apply()
    }

    /**
     * Стирает всё: сеть, ключ клиента, правила, настройки.
     *
     * Ссылка содержит приватный ключ, и «выйти» здесь означает именно стереть его, а не
     * забыть показывать. Вернуться можно только новой ссылкой от того, кто держит сеть.
     */
    fun wipe() = p.edit().clear().apply()

    /** Стирает только правила, не трогая сеть и настройки. */
    fun wipeRules() = p.edit().remove(KEY_RULES).apply()

    companion object {
        /** Режимы обновления сведений о сети. */
        const val MODE_AUTO = "auto"
        const val MODE_ASK = "ask"
        const val MODE_OFF = "off"

        private const val KEY_BUNDLE = "bundle"
        private const val KEY_PASSWORD = "password"
        private const val KEY_VIA_EXIT = "via_exit"
        private const val KEY_RULES = "rules"
        private const val KEY_BRUTAL_UP = "brutal_up"
        private const val KEY_GEO_DAYS = "geo_days"
        private const val KEY_GEO_AUTO = "geo_auto"
        private const val KEY_VERBOSE = "verbose"
        private const val KEY_KEEP_DNS = "keep_dns"
        private const val KEY_NETWORK_HOURS = "network_hours"
        private const val KEY_NETWORK_MODE = "network_mode"
        private const val KEY_NETWORK_CHECKED = "network_checked"
    }
}
