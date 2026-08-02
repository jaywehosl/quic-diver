package ru.qdiver.client

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
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
 * сверху — кто он и что с подпиской, посередине — состояние, внизу — кнопка и цифры.
 *
 * Соседние экраны — свайпами: влево маршрутизация, вправо настройки, вверх управление (только
 * владельцу), вниз журнал (если включён). Раскладка в Shell.
 */
@Composable
fun MainScreen(
    prefs: Prefs,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    hasControl: Boolean,
    hasLog: Boolean,
) {
    var status by remember { mutableStateOf(Core.status()) }
    var previous by remember { mutableStateOf(Core.status()) }
    var running by remember { mutableStateOf(Core.running) }
    var viaExit by remember { mutableStateOf(prefs.viaExit) }
    var saved by remember { mutableStateOf(Core.savedNetwork()) }
    var refreshing by remember { mutableStateOf(false) }

    val net = remember { Core.network() }
    val scope = rememberCoroutineScope()

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

    val downBps = perSecond(status.received - previous.received)
    val upBps = perSecond(status.sent - previous.sent)

    Column(
        Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // ── шапка: кто ты и что с подпиской ─────────────────────────────────────────────
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = status.network.ifEmpty { "сеть" },
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    text = "обновится через ${untilRefresh(prefs)}",
                    fontSize = 12.sp,
                    color = Grey,
                    modifier = Modifier.padding(top = 2.dp),
                )
                if (running && status.connected) {
                    Text(
                        text = "задержка ${status.pingText()} · на связи ${status.uptime()}",
                        fontSize = 12.sp,
                        color = Grey,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
            }

            // Обновить сведения о сети: кнопка по требованию ТЗ, помимо расписания.
            RefreshDot(busy = refreshing) {
                if (!refreshing) {
                    refreshing = true
                    scope.launch {
                        val err = withContext(Dispatchers.IO) { Core.refreshNetwork(prefs) }
                        refreshing = false
                        saved = Core.savedNetwork()
                        Journal.post(
                            if (err != null) "обновить сеть не вышло: $err"
                            else "сеть на связи: узлов ${saved.nodes}"
                        )
                    }
                }
            }
        }

        Spacer(Modifier.weight(1f))

        // ── состояние ───────────────────────────────────────────────────────────────────
        Text(
            text = when {
                !running -> "Отключено"
                status.connected -> "Подключено"
                else -> "Подключаюсь"
            },
            fontSize = 32.sp,
            color = when {
                !running -> Grey
                status.connected -> Green
                else -> Amber
            },
        )
        Text(
            text = "узлов ${nodeCount(saved, net)}",
            fontSize = 13.sp,
            color = Grey,
            modifier = Modifier.padding(top = 4.dp),
        )
        Text(
            // Куда именно выходит трафик, важнее того, какой узел его принял: узлы клиенту не
            // называются вовсе — он их не выбирает.
            text = when {
                !running -> "трафик идёт мимо туннеля"
                status.viaEgress -> "выход через выходные узлы"
                else -> "выход на входном узле"
            },
            fontSize = 13.sp,
            color = Grey,
            modifier = Modifier.padding(top = 2.dp),
        )

        Spacer(Modifier.weight(1f))

        // ── кнопка ──────────────────────────────────────────────────────────────────────
        ConnectButton(
            running = running,
            viaExit = viaExit,
            // Переключатель показывается, только если в сети есть выходные узлы: предлагать
            // выбор, которого нет, — врать.
            hasEgress = net.hasEgress,
            onToggle = { on ->
                viaExit = on
                prefs.viaExit = on
                if (Core.setViaExit(on)) {
                    Journal.post(
                        if (on) "новые соединения идут через выходные узлы"
                        else "новые соединения выходят на входном узле"
                    )
                }
            },
            onClick = { if (running) onDisconnect() else onConnect() },
        )

        // ── цифры ───────────────────────────────────────────────────────────────────────
        Usage(status)

        Row(
            Modifier.fillMaxWidth().padding(top = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Speed("загрузка", downBps, running)
            Speed("отдача", upBps, running)
        }

        Spacer(Modifier.height(12.dp))

        // Подсказка о соседних экранах. Свайп не виден на экране, и человек, не знающий о
        // нём, останется на главном навсегда.
        Text(
            text = hints(hasControl, hasLog),
            fontSize = 10.sp,
            color = Grey,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/**
 * Кнопка подключения с переключателем выхода.
 *
 * Две области в одной кнопке: большая подключает, малая справа переводит трафик на выходные
 * узлы. Малая красная, пока выход не включён, и зелёная, когда включён, — состояние видно
 * издалека, без чтения подписей.
 *
 * Разделены они полностью, каждая со своим нажатием: общая область на две задачи означала бы,
 * что человек, метивший в переключатель, случайно рвёт себе связь.
 */
@Composable
private fun ConnectButton(
    running: Boolean,
    viaExit: Boolean,
    hasEgress: Boolean,
    onToggle: (Boolean) -> Unit,
    onClick: () -> Unit,
) {
    val shape = RoundedCornerShape(28.dp)

    Row(
        Modifier
            .fillMaxWidth()
            .height(72.dp)
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceVariant),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .weight(1f)
                .fillMaxSize()
                .background(if (running) Grey.copy(alpha = 0.25f) else Blue.copy(alpha = 0.85f))
                .clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = if (running) "ОТКЛЮЧИТЬСЯ" else "ПОДКЛЮЧИТЬСЯ",
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                color = Color.White,
            )
        }

        if (hasEgress) {
            Box(
                Modifier
                    .width(110.dp)
                    .fillMaxSize()
                    .background(if (viaExit) Green else Red)
                    .clickable { onToggle(!viaExit) },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = if (viaExit) "ВЫХОД\nВКЛ" else "ВЫХОД\nВЫКЛ",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

/** Кружок обновления сведений о сети. */
@Composable
private fun RefreshDot(busy: Boolean, onClick: () -> Unit) {
    Box(
        Modifier.size(40.dp).clip(RoundedCornerShape(20.dp)).clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
        } else {
            Text("⟳", fontSize = 22.sp, color = Blue)
        }
    }
}

@Composable
private fun Speed(label: String, bps: Long, running: Boolean) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(if (running) speed(bps) else "—", fontSize = 17.sp)
        Text(label, fontSize = 11.sp, color = Grey)
    }
}

@Composable
private fun Usage(status: Status) {
    if (status.limitBytes > 0) {
        LinearProgressIndicator(
            progress = { status.limitFraction },
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        Text(
            text = "${bytes(status.usageTotal)} из ${bytes(status.limitBytes)}" +
                if (status.period.isEmpty()) "" else " · ${status.period}",
            fontSize = 12.sp,
            color = Grey,
            modifier = Modifier.padding(top = 4.dp),
        )
        return
    }
    Text(
        // «Всего» приходит от сети снапшотом. Владельцу снапшоты не приходят — узел отвечает
        // ему сверкой журналов, — поэтому там пока стоит заглушка: расход всех клиентов он и
        // так видит на экране управления.
        text = "за сессию ${bytes(status.sent + status.received)} · всего ${totalText(status)}",
        fontSize = 12.sp,
        color = Grey,
        modifier = Modifier.padding(top = 12.dp),
    )
}

/** Сколько узлов знает клиент. Из ссылки и памяти, а не проверкой живости. */
private fun nodeCount(saved: SavedNetwork, net: NetworkInfo): Int =
    if (saved.nodes > 0) saved.nodes else net.nodes.size

/** Сколько осталось до следующего обновления сведений о сети. */
private fun untilRefresh(prefs: Prefs): String {
    if (prefs.networkMode == Prefs.MODE_OFF) return "вручную"
    val due = prefs.networkCheckedUnix + prefs.networkHours * 3600L
    val left = due - System.currentTimeMillis() / 1000
    return when {
        left <= 0 -> "при запуске"
        left < 3600 -> "${left / 60} мин"
        else -> "${left / 3600} ч"
    }
}

/** Расход по сети. Пока сеть его не сообщила, стоит заглушка. */
private fun totalText(status: Status): String =
    if (status.usageTotal > 0) bytes(status.usageTotal) else "∞"

private fun hints(hasControl: Boolean, hasLog: Boolean): String {
    val parts = mutableListOf("← маршрутизация", "настройки →")
    if (hasControl) parts.add(0, "↑ управление")
    if (hasLog) parts.add("↓ журнал")
    return parts.joinToString("   ")
}

/** Скорость за секунду. Опрос идёт раз в секунду, поэтому разница и есть скорость. */
private fun perSecond(delta: Long): Long = if (delta < 0) 0 else delta
