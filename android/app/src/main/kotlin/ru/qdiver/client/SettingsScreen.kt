package ru.qdiver.client

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Настройки.
 *
 * Всё, кроме потолка скорости, сохраняется в момент касания: галку, которую надо подтверждать,
 * человек подтверждать не станет.
 */
@Composable
fun SettingsScreen(prefs: Prefs, onBack: () -> Unit, onWiped: () -> Unit) {
    val net = remember { Core.network() }
    val owner = remember { Core.owner() }
    val scope = rememberCoroutineScope()

    var geo by remember { mutableStateOf(Core.geo()) }
    var fetching by remember { mutableStateOf(false) }
    var geoDays by remember { mutableStateOf(prefs.geoDays) }
    var geoAuto by remember { mutableStateOf(prefs.geoAuto) }
    var keepDNS by remember { mutableStateOf(prefs.keepDNS) }
    var verbose by remember { mutableStateOf(prefs.verbose) }
    var brutal by remember { mutableStateOf(if (prefs.brutalUp > 0) prefs.brutalUp.toString() else "") }
    var confirmWipe by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf("") }

    var saved by remember { mutableStateOf(Core.savedNetwork()) }
    var refreshing by remember { mutableStateOf(false) }
    var netProblem by remember { mutableStateOf("") }
    var netMode by remember { mutableStateOf(prefs.networkMode) }
    var netHours by remember { mutableStateOf(prefs.networkHours) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Text("Настройки", fontSize = 22.sp, modifier = Modifier.padding(bottom = 8.dp))

        Header("Сеть")
        // Ссылка не показывается: в ней приватный ключ клиента, и держать его строкой на
        // экране незачем.
        Text(if (net.name.isEmpty()) "сеть задана" else "сеть ${net.name}", fontSize = 15.sp)
        if (owner.owner) {
            Text(
                "эта сеть твоя: узлов ${owner.nodes}, записей в журнале ${owner.records}",
                fontSize = 12.sp,
                color = Green,
                modifier = Modifier.padding(top = 4.dp),
            )
            Text(owner.genesis, fontSize = 10.sp, color = Grey)
        }
        Hint(
            if (!Core.running) "Галка «через выходные узлы» — на главном экране, рядом с кнопкой."
            else if (net.hasEgress) "В сети есть выходные узлы."
            else "Выходных узлов в сети нет — весь трафик выходит на входном узле."
        )
        OutlinedButton(
            onClick = { confirmWipe = true },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        ) { Text("Сбросить данные") }
        Hint("Стирает сеть, ключ и все настройки. Вернуться можно будет только новой ссылкой.")

        Header("Скорость")
        OutlinedTextField(
            value = brutal,
            onValueChange = { value ->
                brutal = value.filter { it.isDigit() }
                prefs.brutalUp = brutal.toIntOrNull() ?: 0
            },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            placeholder = { Text("Мбит/с, пусто — как скажет сеть") },
            modifier = Modifier.fillMaxWidth(),
        )
        Hint(
            if (net.brutalUpMbps <= 0)
                "Потолок отдачи. Сеть его не задаёт — работает обычный Cubic. Число обязано" +
                    " отвечать настоящему каналу: алгоритм не сбавляет при потерях."
            else
                "Потолок отдачи. Сеть предлагает ${net.brutalUpMbps} Мбит/с" +
                    (if (net.brutalDownMbps > 0) ", на приём ${net.brutalDownMbps}" else "") +
                    ". Свой канал ты знаешь лучше — но число обязано отвечать настоящему."
        )

        Header("Списки сайтов")
        Text(
            if (geo.missing) "Не скачаны — правила по категориям не работают"
            else "Версия ${geo.installed} · списков доменов ${geo.sites}, подсетей ${geo.ips}",
            fontSize = 14.sp,
            color = if (geo.missing) Amber else MaterialTheme.colorScheme.onSurface,
        )
        if (problem.isNotEmpty()) {
            Text(problem, fontSize = 12.sp, color = Red, modifier = Modifier.padding(top = 4.dp))
        }
        OutlinedButton(
            onClick = {
                fetching = true
                problem = ""
                scope.launch {
                    val err = withContext(Dispatchers.IO) {
                        runCatching { Core.fetchGeo(prefs) }.exceptionOrNull()?.message
                    }
                    fetching = false
                    if (err != null) problem = err else geo = Core.geo(fresh = true)
                }
            },
            enabled = !fetching,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        ) {
            if (fetching) {
                CircularProgressIndicator(Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                Text("качаю…")
            } else {
                Text(if (geo.missing) "Скачать базы" else "Проверить обновление")
            }
        }
        Hint("Около 28 МБ. Подключаться для этого не нужно: базы идут по связи с узлом, а не" +
            " через туннель.")

        Hint("Сверяться со свежестью:")
        Row {
            listOf(1 to "раз в сутки", 7 to "раз в неделю", 30 to "раз в месяц").forEach { (days, label) ->
                Text(
                    label,
                    fontSize = 13.sp,
                    color = if (geoDays == days) Blue else Grey,
                    modifier = Modifier
                        .clickable { geoDays = days; prefs.geoDays = days }
                        .padding(end = 18.dp, top = 4.dp, bottom = 8.dp),
                )
            }
        }
        Toggle("обновлять самому", geoAuto) { geoAuto = it; prefs.geoAuto = it }
        Hint("Включено — при подключении после срока клиент скачает свежие базы сам. Выключено —" +
            " только проверит и скажет: двадцать восемь мегабайт из сотового трафика без спроса" +
            " уносить нельзя.")

        Header("Служба имён")
        Toggle("перехватывать шифрованный DNS", keepDNS) {
            keepDNS = it
            prefs.keepDNS = it
        }
        Hint("Браузер со своим DoH разрешает имена мимо туннеля — и правила по доменам" +
            " перестают работать целиком, молча. Перехват возвращает разрешение имён клиенту:" +
            " известные резолверы DoH получают отказ, DNS over TLS обрывается, и браузер" +
            " откатывается на системный резолвер. Применится после переподключения.")

        Header("Журнал")
        Toggle("подробный журнал", verbose) {
            verbose = it
            prefs.verbose = it
            Core.setVerbose(it)
        }
        Hint("Строка на каждый поток: куда пошёл, через выход или нет, по какому правилу.")

        Header("Сведения о сети")
        Text(
            if (!saved.known) "Сеть ещё не рассказывала о себе — узлы берутся из ссылки"
            else "Входных узлов ${saved.nodes} · обновлено ${ago(saved.savedUnix)}",
            fontSize = 14.sp,
            color = if (saved.known) MaterialTheme.colorScheme.onSurface else Amber,
        )
        if (netProblem.isNotEmpty()) {
            Text(netProblem, fontSize = 12.sp, color = Red, modifier = Modifier.padding(top = 4.dp))
        }
        OutlinedButton(
            onClick = {
                refreshing = true
                netProblem = ""
                scope.launch {
                    val err = withContext(Dispatchers.IO) { Core.refreshNetwork(prefs) }
                    refreshing = false
                    if (err != null) netProblem = err else saved = Core.savedNetwork()
                }
            },
            enabled = !refreshing,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        ) {
            if (refreshing) {
                CircularProgressIndicator(Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                Text("спрашиваю…")
            } else {
                Text("Обновить сейчас")
            }
        }
        Hint("Сеть меняется: узлы добавляют, адреса переезжают. Клиент запоминает список и берёт" +
            " его при следующем запуске — ссылка после этого нужна ровно один раз. Подключаться" +
            " для обновления не нужно.")

        Hint("Спрашивать сеть:")
        Row {
            listOf(
                Prefs.MODE_AUTO to "самому",
                Prefs.MODE_ASK to "спрашивать",
                Prefs.MODE_OFF to "вручную",
            ).forEach { (mode, label) ->
                Text(
                    label,
                    fontSize = 13.sp,
                    color = if (netMode == mode) Blue else Grey,
                    modifier = Modifier
                        .clickable { netMode = mode; prefs.networkMode = mode }
                        .padding(end = 18.dp, top = 4.dp, bottom = 8.dp),
                )
            }
        }
        if (netMode != Prefs.MODE_OFF) {
            Hint("Не чаще чем раз в $netHours ч:")
            Row {
                listOf(1, 6, 12, 24).forEach { hours ->
                    Text(
                        "$hours ч",
                        fontSize = 13.sp,
                        color = if (netHours == hours) Blue else Grey,
                        modifier = Modifier
                            .clickable { netHours = hours; prefs.networkHours = hours }
                            .padding(end = 18.dp, top = 4.dp, bottom = 8.dp),
                    )
                }
            }
        }
        Hint(
            when (netMode) {
                Prefs.MODE_AUTO -> "При запуске, если срок вышел, клиент обновит список сам."
                Prefs.MODE_ASK -> "При запуске, если срок вышел, клиент спросит."
                else -> "Только по кнопке выше. Пока клиент работает, сеть всё равно присылает" +
                    " изменения сама — этот выбор про то, что делать между запусками."
            }
        )

        Header("Входные узлы")
        if (!Core.running) {
            Hint("Узлы приезжают из сети. Подключись, чтобы их увидеть.")
        } else if (net.nodes.isEmpty()) {
            Hint("Сеть пока не назвала ни одного входного узла.")
        } else {
            net.nodes.forEach { node ->
                Text("${node.id}", fontSize = 14.sp, modifier = Modifier.padding(top = 6.dp))
                Text("${node.domain} · адресов ${node.endpoints}", fontSize = 11.sp, color = Grey)
            }
            Hint("К этим узлам клиент обращается сразу ко всем и работает с тем, кто ответил" +
                " первым.")
        }

        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth().padding(top = 24.dp)) {
            Text("Назад")
        }
    }

    if (confirmWipe) {
        AlertDialog(
            onDismissRequest = { confirmWipe = false },
            title = { Text("Сбросить данные?") },
            text = {
                Text("Сеть, ключ и настройки будут стёрты. Чтобы вернуться, понадобится новая" +
                    " ссылка от того, кто держит сеть.")
            },
            confirmButton = {
                TextButton(onClick = {
                    prefs.wipe()
                    confirmWipe = false
                    onWiped()
                }) { Text("Стереть") }
            },
            dismissButton = { TextButton(onClick = { confirmWipe = false }) { Text("Отмена") } },
        )
    }
}

@Composable
private fun Header(title: String) {
    HorizontalDivider(Modifier.padding(top = 20.dp))
    Text(title, fontSize = 15.sp, color = Green, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
}

@Composable
private fun Hint(text: String) {
    Text(text, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(top = 4.dp))
}

@Composable
private fun Toggle(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Switch(checked = checked, onCheckedChange = onChange)
        Text(label, Modifier.padding(start = 12.dp), fontSize = 14.sp)
    }
}
