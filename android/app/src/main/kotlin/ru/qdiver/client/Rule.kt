package ru.qdiver.client

import org.json.JSONArray
import org.json.JSONObject

/** Что делать с потоком. Те же три исхода, что и у глобальной галки, только для своего куска. */
enum class Act(val wire: String, val words: String) {
    DIRECT("direct", "напрямую"),
    EGRESS("egress", "через выход"),
    BLOCK("block", "блокировать");

    companion object {
        fun of(wire: String) = entries.firstOrNull { it.wire == wire } ?: EGRESS
    }
}

/** Ступень правила: она же секция на экране, она же сила в споре двух правил. */
enum class Kind(val title: String, val about: String) {
    SITE("Сайты", "Домен и все его поддомены. Сильнее списков и приложений."),
    LIST("Списки", "Категории из баз geosite и geoip."),
    APP("Приложения", "Слабее сайтов и списков: правило по имени всегда важнее.")
}

/**
 * Правило маршрутизации в том виде, в каком его хранит и показывает приложение.
 *
 * Формат тот же, что понимает ядро, — список таких объектов уезжает в `Mobile.setRules` как
 * есть. Своего представления приложение не заводит намеренно: лишний перевод туда-обратно
 * означал бы два места, где формат может разъехаться.
 */
data class Rule(
    /** Условие целиком, как его понимает ядро: `domain:yandex.ru`, `geosite:ru`, `process:…`. */
    val match: String,
    val action: Act = Act.EGRESS,
    val comment: String = "",
    /** Соблюдать всегда: правило не перебивается никаким другим. */
    val force: Boolean = false,
    /** Выключено: остаётся в списке, но ни на что не влияет. */
    val off: Boolean = false,
) {
    val kind: Kind
        get() = when {
            match.startsWith("process:") -> Kind.APP
            match.startsWith("geosite:") || match.startsWith("geoip:") -> Kind.LIST
            else -> Kind.SITE
        }

    /** Нужны ли правилу базы. Без них такое правило не сработает никогда. */
    val needsGeo: Boolean
        get() = match.startsWith("geosite:") || match.startsWith("geoip:")

    /** То, что человек видит в строке: условие без служебного префикса. */
    val title: String
        get() = comment.ifEmpty { match.substringAfter(':', match) }

    fun toJson(): JSONObject = JSONObject().apply {
        put("match", JSONArray().put(match))
        put("action", action.wire)
        if (comment.isNotEmpty()) put("comment", comment)
        if (force) put("force", true)
        if (off) put("off", true)
    }

    companion object {
        /**
         * Правило по имени сайта.
         *
         * Ввод чистится: `*.yandex.ru`, `https://yandex.ru/`, `www.yandex.ru` — всё это человек
         * пишет, имея в виду одно и то же. Звёздочка тут особенно коварна: `domain:` и так
         * значит «домен со всеми поддоменами», а `domain:*.yandex.ru` ищет буквальный суффикс
         * со звёздочкой и не совпадает никогда — молча, без единой ошибки.
         */
        fun site(input: String): Rule? {
            var s = input.trim().lowercase()
            s = s.removePrefix("https://").removePrefix("http://")
            s = s.substringBefore('/').substringBefore('?')
            s = s.removePrefix("*.").removePrefix(".")
            s = s.removePrefix("www.")
            s = s.trim('.')
            if (s.isEmpty() || !s.contains('.')) return null
            return Rule(match = "domain:$s", action = Act.DIRECT)
        }

        fun list(name: String, isIP: Boolean) =
            Rule(match = (if (isIP) "geoip:" else "geosite:") + name, action = Act.BLOCK)

        fun app(pkg: String, label: String) =
            Rule(match = "process:$pkg", comment = label, action = Act.EGRESS)

        /** Разбирает сохранённый список. Испорченное хранилище даёт пустой список, а не отказ. */
        fun parseAll(json: String): List<Rule> {
            if (json.isBlank()) return emptyList()
            return runCatching {
                val arr = JSONArray(json)
                (0 until arr.length()).mapNotNull { i ->
                    val o = arr.getJSONObject(i)
                    val match = o.optJSONArray("match")?.optString(0).orEmpty()
                    if (match.isEmpty()) null
                    else Rule(
                        match = match,
                        action = Act.of(o.optString("action")),
                        comment = o.optString("comment"),
                        force = o.optBoolean("force"),
                        off = o.optBoolean("off"),
                    )
                }
            }.getOrDefault(emptyList())
        }

        /**
         * Собирает список обратно в JSON.
         *
         * Порядок важен: внутри одной ступени побеждает то правило, что раньше. Поэтому список
         * сохраняется в том же виде, в каком его видит человек на экране.
         */
        fun toJson(rules: List<Rule>): String =
            JSONArray().apply { rules.forEach { put(it.toJson()) } }.toString()
    }
}
