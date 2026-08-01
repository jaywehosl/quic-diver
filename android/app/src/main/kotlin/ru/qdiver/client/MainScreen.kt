package ru.qdiver.client

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Главный экран.
 *
 * Вопрос, с которым человек открывает приложение, один: работает ли и через кого. Поэтому
 * сверху состояние, под ним галка и кнопка, ниже числа, и только в самом низу журнал — он
 * нужен, когда что-то пошло не так.
 */
@Composable
fun MainScreen(
    prefs: Prefs,
    journal: Journal,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onRouting: () -> Unit,
    onSettings: () -> Unit,
) {
    var status by remember { mutableStateOf(Core.status()) }
    var previous by remember { mutableStateOf(Core.status()) }
    var running by remember { mutableStateOf(Core.running) }
    var viaExit by remember { mutableStateOf(prefs.viaExit) }

    var askNetwork by remember { mutableStateOf(false) }

    // Раз в секунду: скорость считается разницей опросов, и знать, как часто спрашивают,
    // может только тот, кто спрашивает.
    LaunchedEffect(Unit) {
        while (true) {
            previous = status
            status = Core.status()
            running = Core.running
            delay(1000)
        }
    }

    // Сведения о сети между запусками (решение 007 §4).
    //
    // Пока клиент работает, это не нужно вовсе: сеть присылает изменения сама, на каждую
    // правку журнала. Речь о другом — приложение не открывали неделю, за это время узел сменил
    // адрес, и без обновления человек узнал бы об этом в момент, когда ничего не подключается.
    LaunchedEffect(Unit) {
        if (!prefs.configured || Core.running || !prefs.networkDue()) return@LaunchedEffect
        when (prefs.networkMode) {
            Prefs.MODE_ASK -> askNetwork = true
            Prefs.MODE_AUTO -> refreshNetwork(prefs)
        }
    }

    val downBps = perSecond(status.received - previous.received)
    val upBps = perSecond(status.sent - previous.sent)

    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Text(
            text = when {
                !running -> "Отключено"
                status.connected -> "Подключено"
                else -> "Подключаюсь"
            },
            fontSize = 30.sp,
            color = when {
                !running -> Grey
                status.connected -> Green
                else -> Amber
            },
            modifier = Modifier.fillMaxWidth(),
            textAlign = TextAlign.Center,
        )
        Text(
            text = route(status, running),
            fontSize = 13.sp,
            color = Grey,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 16.dp),
            textAlign = TextAlign.Center,
        )

        // Галка стоит вплотную к кнопке: ТЗ ставит её именно сюда, и переключают её часто.
        // Работает на ходу — умолчание маршрутизации меняется без переподключения.
        Row(
            Modifier.fillMaxWidth().padding(bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Switch(
                checked = viaExit,
                onCheckedChange = { on ->
                    viaExit = on
                    prefs.viaExit = on
                    if (Core.setViaExit(on)) {
                        Journal.post(
                            if (on) "новые соединения идут через выходные узлы"
                            else "новые соединения выходят на входном узле"
                        )
                    }
                },
            )
            Text("через выходные узлы", Modifier.padding(start = 12.dp), fontSize = 15.sp)
        }

        Button(
            onClick = { if (running) onDisconnect() else onConnect() },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (running) "Отключить" else "Подключить")
        }

        if (running) {
            Text(
                text = "↓ ${speed(downBps)}   ↑ ${speed(upBps)}",
                fontSize = 16.sp,
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                textAlign = TextAlign.Center,
            )
            Usage(status)
            Text(
                text = details(status),
                fontSize = 12.sp,
                color = Grey,
                modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                textAlign = TextAlign.Center,
            )
        }

        Spacer(Modifier.height(16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onRouting, modifier = Modifier.weight(1f)) {
                Text("Маршрутизация")
            }
            OutlinedButton(onClick = onSettings, modifier = Modifier.weight(1f)) {
                Text("Настройки")
            }
        }

        Spacer(Modifier.height(12.dp))
        LazyColumn(Modifier.fillMaxWidth().weight(1f)) {
            items(journal.lines.asReversed()) { line ->
                Text(line, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(vertical = 1.dp))
            }
        }
    }

    if (askNetwork) {
        val scope = rememberCoroutineScope()
        AlertDialog(
            onDismissRequest = { askNetwork = false },
            title = { Text("Спросить сеть о узлах?") },
            text = {
                Text("Список входных узлов не обновлялся ${ago(Core.savedNetwork().savedUnix)}." +
                    " Обновление весит килобайты и идёт без туннеля.")
            },
            confirmButton = {
                TextButton(onClick = {
                    askNetwork = false
                    scope.launch { refreshNetwork(prefs) }
                }) { Text("Обновить") }
            },
            dismissButton = {
                TextButton(onClick = {
                    // Отложено — значит отложено до следующего срока, а не до следующего
                    // открытия приложения: спрашивать на каждый запуск изводит.
                    prefs.networkCheckedUnix = System.currentTimeMillis() / 1000
                    askNetwork = false
                }) { Text("Потом") }
            },
        )
    }
}

/** Спрашивает сеть о узлах и пишет о результате в журнал. */
private suspend fun refreshNetwork(prefs: Prefs) {
    val err = withContext(Dispatchers.IO) { Core.refreshNetwork(prefs) }
    if (err != null) {
        Journal.post("список узлов обновить не вышло: $err")
        return
    }
    val saved = Core.savedNetwork()
    Journal.post("сеть на связи: входных узлов ${saved.nodes}")
}

@Composable
private fun Usage(status: Status) {
    if (status.limitBytes > 0) {
        LinearProgressIndicator(
            progress = { status.limitFraction },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Text(
            text = "${bytes(status.usageTotal)} из ${bytes(status.limitBytes)}" +
                if (status.period.isEmpty()) "" else " · ${status.period}",
            fontSize = 12.sp,
            color = Grey,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            textAlign = TextAlign.Center,
        )
        return
    }
    Text(
        text = if (status.usageTotal > 0) "по сети: ${bytes(status.usageTotal)} · лимита нет"
        else "лимита нет",
        fontSize = 12.sp,
        color = Grey,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        textAlign = TextAlign.Center,
    )
}

/**
 * route описывает путь трафика словами.
 *
 * Имени выходного узла здесь нет и быть не может: клиент его не знает. Выход подбирает гонка
 * на входном узле, а клиенту сообщается только то, ушёл поток через выход или нет.
 */
private fun route(s: Status, running: Boolean): String {
    if (!running) {
        return if (s.network.isEmpty()) "" else "сеть ${s.network}"
    }
    if (!s.connected) {
        return if (s.node.isEmpty()) "ищу узел" else "связь с ${s.node} потеряна, ищу заново"
    }

    val where = when {
        s.viaEgress -> " → через выход"
        s.viaExit -> " → выхода ещё не было"
        else -> " · наружу здесь же"
    }
    val up = s.uptime()
    return "вход ${s.node}$where" + if (up.isEmpty()) "" else " · $up"
}

private fun details(s: Status): String = buildString {
    append("за сеанс ${bytes(s.sent + s.received)}")
    if (s.deviceLimit > 0) append(" · устройств ${s.devices} из ${s.deviceLimit}")
    if (s.rules > 0) append(" · правил ${s.rules}")
    if (s.nodes > 0) append(" · узлов ${s.nodes}")
}

/** Отрицательная разница означает, что ядро перезапустилось и счётчики начались заново. */
private fun perSecond(delta: Long): Long = if (delta <= 0) 0 else delta
