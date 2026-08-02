package ru.qdiver.client

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Управление сетью. Видно только владельцу.
 *
 * # Что здесь происходит на самом деле
 *
 * Ни одна кнопка не приказывает серверам. Каждая дописывает подписанную запись в журнал, и
 * журнал сверяется с любым живым узлом — дальше запись расходится по сети сама.
 *
 * Отсюда правило для этого экрана: правка удалась, даже если сеть о ней не узнала. Узел в
 * отключке получит её позже, от соседей. Поэтому «сеть пока не в курсе» показывается жёлтым
 * предупреждением, а не красной ошибкой, и список после этого всё равно обновляется.
 */
@Composable
fun ControlScreen(onBack: () -> Unit) {
    var owner by remember { mutableStateOf(Core.owner()) }
    var clients by remember { mutableStateOf(Core.clients()) }
    var nodes by remember { mutableStateOf(Core.nodes()) }
    var settings by remember { mutableStateOf(Core.networkSettings()) }

    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf("") }
    var warning by remember { mutableStateOf("") }
    var issued by remember { mutableStateOf<Pair<String, String>?>(null) }

    var addingClient by remember { mutableStateOf(false) }
    var acting by remember { mutableStateOf<ClientInfo?>(null) }

    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current

    // Любая правка идёт одинаково: выполнить в фоне, показать беду либо предупреждение,
    // перечитать списки. Перечитывать надо в любом случае — запись легла в журнал даже тогда,
    // когда разнести её не вышло.
    fun act(block: suspend () -> String?) {
        busy = true
        problem = ""
        warning = ""
        scope.launch {
            val err = withContext(Dispatchers.IO) { block() }
            busy = false
            if (err != null) {
                if (err.contains("сеть пока о ней не знает")) warning = err else problem = err
            }
            clients = Core.clients()
            nodes = Core.nodes()
            settings = Core.networkSettings()
            owner = Core.owner()
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Управление", fontSize = 22.sp)
                Text(
                    "сеть ${owner.network} · записей ${owner.records}",
                    fontSize = 12.sp,
                    color = Grey,
                )
            }
            if (busy) CircularProgressIndicator(Modifier.padding(start = 8.dp), strokeWidth = 2.dp)
        }

        if (problem.isNotEmpty()) {
            Text(problem, fontSize = 12.sp, color = Red, modifier = Modifier.padding(top = 8.dp))
        }
        if (warning.isNotEmpty()) {
            Text(warning, fontSize = 12.sp, color = Amber, modifier = Modifier.padding(top = 8.dp))
        }

        // ── клиенты ─────────────────────────────────────────────────────────────────────
        Header("Клиенты (${clients.size})")
        if (clients.isEmpty()) {
            Hint("Никого нет. Заведи клиента — он получит свою ссылку.")
        }
        clients.forEach { c ->
            Column(
                Modifier
                    .fillMaxWidth()
                    .clickable { acting = c }
                    .padding(vertical = 6.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        c.id + if (c.label.isEmpty()) "" else " · ${c.label}",
                        fontSize = 15.sp,
                        color = if (c.suspended) Grey else Green,
                        modifier = Modifier.weight(1f),
                    )
                    if (c.suspended) Text("приостановлен", fontSize = 11.sp, color = Amber)
                }
                Text(c.describe(), fontSize = 11.sp, color = Grey)
            }
            HorizontalDivider()
        }
        OutlinedButton(
            onClick = { addingClient = true },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        ) { Text("Завести клиента") }

        // ── узлы ────────────────────────────────────────────────────────────────────────
        Header("Узлы (${nodes.size})")
        nodes.forEach { n ->
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Text("${n.id} · ${n.roles.joinToString(", ")}", fontSize = 15.sp)
                Text(n.domain, fontSize = 11.sp, color = Grey)
                Text(n.endpoints.joinToString(", "), fontSize = 10.sp, color = Grey)
                Row(Modifier.padding(top = 4.dp)) {
                    listOf("ingress" to "вход", "egress" to "выход", "both" to "обе").forEach { (role, label) ->
                        Text(
                            label,
                            fontSize = 12.sp,
                            color = if (n.roles.joinToString(",") == role ||
                                (role == "both" && n.roles.size == 2)
                            ) Blue else Grey,
                            modifier = Modifier
                                .clickable(enabled = !busy) { act { Core.updateNode(n.id, role) } }
                                .padding(end = 16.dp),
                        )
                    }
                    Text(
                        "убрать",
                        fontSize = 12.sp,
                        color = Red,
                        modifier = Modifier.clickable(enabled = !busy) {
                            act { Core.revokeNode(n.id) }
                        },
                    )
                }
            }
            HorizontalDivider()
        }
        Hint("Роль меняется записью в журнал. Сам сервер продолжает работать: остановить его" +
            " отсюда нельзя — журнал описывает сеть, а не управляет чужими машинами.")

        // ── параметры сети ──────────────────────────────────────────────────────────────
        Header("Параметры сети")
        SettingsBlock(settings, busy) { up, down, mesh, dns1, dns2 ->
            act { Core.setNetworkSettings(up, down, mesh, dns1, dns2) }
        }
        OutlinedButton(
            onClick = { act { Core.flushDNS() } },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        ) { Text("Сбросить кеш имён на узлах") }
        Hint("Не команда, а метка в журнале: узел, увидевший её новее применённой, чистит кеш." +
            " Так сброс срабатывает и на узлах, которых сейчас нет в живых.")

        OutlinedButton(
            onClick = { act { Core.syncNetwork() } },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
        ) { Text("Сверить журнал с сетью") }
        Hint("Забирает правки, сделанные с другого устройства — например, запасной ссылкой.")

        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text("Назад")
        }
    }

    if (addingClient) {
        AddClientDialog(
            onDismiss = { addingClient = false },
            onAdd = { id, label, gb, devices, days, period, password ->
                addingClient = false
                busy = true
                scope.launch {
                    val res = withContext(Dispatchers.IO) {
                        runCatching { Core.addClient(id, label, gb, devices, days, period, password) }
                    }
                    busy = false
                    res.onSuccess { issued = id to it }
                        .onFailure { problem = it.message ?: "клиент не завёлся" }
                    clients = Core.clients()
                }
            },
        )
    }

    acting?.let { c ->
        ClientActions(
            client = c,
            onDismiss = { acting = null },
            onSuspend = { acting = null; act { Core.suspendClient(c.id, !c.suspended) } },
            onRevoke = { acting = null; act { Core.revokeClient(c.id) } },
            onReissue = {
                acting = null
                busy = true
                scope.launch {
                    val res = withContext(Dispatchers.IO) {
                        runCatching { Core.reissueClient(c.id, "") }
                    }
                    busy = false
                    res.onSuccess { issued = c.id to it }
                        .onFailure { problem = it.message ?: "перевыпуск не вышел" }
                    clients = Core.clients()
                }
            },
        )
    }

    issued?.let { (id, uri) ->
        AlertDialog(
            onDismissRequest = { issued = null },
            title = { Text("Ссылка для $id") },
            text = {
                Column {
                    Text(uri, fontSize = 10.sp, color = Grey)
                    Hint("Отдай её человеку. Второй раз она не покажется — перевыпуск создаёт" +
                        " новый ключ и убивает прежний.")
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("ссылка $id", uri))
                }) { Text("Скопировать") }
            },
            dismissButton = { TextButton(onClick = { issued = null }) { Text("Закрыть") } },
        )
    }
}

/** Ввод параметров нового клиента. */
@Composable
private fun AddClientDialog(
    onDismiss: () -> Unit,
    onAdd: (String, String, Int, Int, Int, String, String) -> Unit,
) {
    var id by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var gb by remember { mutableStateOf("") }
    var devices by remember { mutableStateOf("") }
    var days by remember { mutableStateOf("") }
    var period by remember { mutableStateOf("monthly") }
    var password by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Новый клиент") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(
                    value = id,
                    onValueChange = { id = it },
                    label = { Text("имя") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("подпись, необязательно") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                Number("трафик, ГБ (пусто — без потолка)", gb) { gb = it }
                Row(Modifier.padding(top = 4.dp)) {
                    listOf("daily" to "сутки", "weekly" to "неделя", "monthly" to "месяц").forEach { (p, t) ->
                        Text(
                            t,
                            fontSize = 13.sp,
                            color = if (period == p) Blue else Grey,
                            modifier = Modifier.clickable { period = p }.padding(end = 16.dp),
                        )
                    }
                }
                Number("устройств (пусто — без счёта)", devices) { devices = it }
                Number("дней доступа (пусто — бессрочно)", days) { days = it }
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("пароль ссылки, необязательно") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = id.isNotBlank(),
                onClick = {
                    onAdd(
                        id.trim(), label.trim(),
                        gb.toIntOrNull() ?: 0,
                        devices.toIntOrNull() ?: 0,
                        days.toIntOrNull() ?: 0,
                        if ((gb.toIntOrNull() ?: 0) > 0) period else "",
                        password,
                    )
                },
            ) { Text("Завести") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

/** Что можно сделать с клиентом. */
@Composable
private fun ClientActions(
    client: ClientInfo,
    onDismiss: () -> Unit,
    onSuspend: () -> Unit,
    onRevoke: () -> Unit,
    onReissue: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(client.id) },
        text = {
            Column {
                Text(client.describe(), fontSize = 12.sp, color = Grey)
                Hint("Приостановка обратима: ключ жив, история цела. Отзыв — нет: ключ мёртв," +
                    " и вернуть человека можно только новой ссылкой.")
            }
        },
        confirmButton = {
            Column {
                TextButton(onClick = onSuspend) {
                    Text(if (client.suspended) "Вернуть в строй" else "Приостановить")
                }
                TextButton(onClick = onReissue) { Text("Перевыпустить ключ") }
                TextButton(onClick = onRevoke) { Text("Отозвать", color = Red) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
    )
}

/** Параметры сети: потолки и резолверы. */
@Composable
private fun SettingsBlock(
    s: NetSettings,
    busy: Boolean,
    onApply: (Int, Int, Int, String, String) -> Unit,
) {
    var up by remember(s) { mutableStateOf(s.up.toString()) }
    var down by remember(s) { mutableStateOf(s.down.toString()) }
    var mesh by remember(s) { mutableStateOf(s.mesh.toString()) }
    var dns1 by remember(s) { mutableStateOf(s.dnsPrimary) }
    var dns2 by remember(s) { mutableStateOf(s.dnsSecondary) }

    Number("потолок вверх, Мбит/с", up) { up = it }
    Number("потолок вниз, Мбит/с", down) { down = it }
    Number("между узлами, Мбит/с", mesh) { mesh = it }
    OutlinedTextField(
        value = dns1,
        onValueChange = { dns1 = it },
        label = { Text("основной резолвер") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    )
    OutlinedTextField(
        value = dns2,
        onValueChange = { dns2 = it },
        label = { Text("запасной резолвер") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    )
    Button(
        onClick = {
            onApply(
                up.toIntOrNull() ?: 0,
                down.toIntOrNull() ?: 0,
                mesh.toIntOrNull() ?: 0,
                dns1.trim(), dns2.trim(),
            )
        },
        enabled = !busy,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) { Text("Применить к сети") }
    Hint("Потолки доезжают до живых соединений, не разрывая их: узел переставляет число в" +
        " контроллере. Включить BRUTAL там, где его не было, на ходу нельзя — алгоритм" +
        " выбирается при установлении связи.")
}

@Composable
private fun Number(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = { v -> onChange(v.filter { it.isDigit() }) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    )
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
