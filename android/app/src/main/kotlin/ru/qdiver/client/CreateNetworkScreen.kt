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
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Создание сети (решение 007 §2 и §3).
 *
 * Сеть рождается здесь, на устройстве, офлайн: два ключа владельца и подписанная запись
 * генезиса. Сервера в этот момент не существует ни одного, и это не недоработка — узел не может
 * выдать ссылку владельцу, потому что не знает ни сети, ни ключей.
 *
 * Кнопку «создать сеть» видит каждый, и это безвредно: посторонний создаст **свою** сеть, с
 * другими ключами и другим отпечатком. К чужим узлам она не подойдёт — у них в конфиге чужой
 * отпечаток. Он получит сеть без единого узла.
 *
 * # Почему ссылки выдаются в самом конце
 *
 * Ссылка — это не только ключ, но и способ до сети добраться: узлы, их адреса, потолки. Пока
 * первый узел не поднят, ничего этого не существует, и выданная в начале ссылка содержит ключ
 * без единого адреса. Её обладателю некуда идти — и при первой обкатке вышло именно так:
 * владелец со ссылкой на руках не смог подключиться к собственной сети.
 *
 * Поэтому порядок такой: параметры → пароль → развёртывание узла → включение узла → и только
 * потом ссылки, собранные из журнала, где узел уже записан.
 */
private enum class Step { PARAMS, PASSWORD, DEPLOY, WAITING, LINKS, CONFIRM }

@Composable
fun CreateNetworkScreen(prefs: Prefs, onBack: () -> Unit, onDone: () -> Unit) {
    var step by remember { mutableStateOf(Step.PARAMS) }

    var name by remember { mutableStateOf("") }
    var up by remember { mutableStateOf("100") }
    var down by remember { mutableStateOf("300") }
    var mesh by remember { mutableStateOf("500") }

    var pass1 by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }

    var working by remember { mutableStateOf("") }
    var spare by remember { mutableStateOf("") }
    var genesis by remember { mutableStateOf("") }

    var nodeId by remember { mutableStateOf("") }
    var domain by remember { mutableStateOf("") }
    var deployKey by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    // Из чего собран показанный ключ. Поля правятся и после сборки, а ключ сам собой не
    // меняется — и человек уносит на сервер строку, не отвечающую тому, что видит на экране.
    var keyFrom by remember { mutableStateOf("") }
    var showPass by remember { mutableStateOf(false) }

    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf("") }
    var adopted by remember { mutableStateOf("") }

    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Text("Создать сеть", fontSize = 22.sp, modifier = Modifier.padding(bottom = 4.dp))
        Text(stepHint(step), fontSize = 12.sp, color = Grey, modifier = Modifier.padding(bottom = 12.dp))

        if (problem.isNotEmpty()) {
            Text(problem, fontSize = 13.sp, color = Red, modifier = Modifier.padding(bottom = 8.dp))
        }

        when (step) {
            Step.PARAMS -> {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it; problem = "" },
                    label = { Text("имя сети") },
                    placeholder = { Text("qdiver") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Hint("Имя видит только тот, у кого есть ссылка. Оно попадёт в подписанную запись" +
                    " и потом не меняется.")

                Header("Потолки скорости")
                Mbps("от клиента вверх", up) { up = it }
                Mbps("к клиенту вниз", down) { down = it }
                Mbps("между узлами", mesh) { mesh = it }
                Hint("BRUTAL не сбавляет при потерях, поэтому числа обязаны отвечать настоящим" +
                    " каналам. Поменять их можно потом, записью в журнал.")

                Button(
                    onClick = {
                        if (name.isBlank()) problem = "введи имя сети" else step = Step.PASSWORD
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                ) { Text("Дальше") }
                OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Text("Назад")
                }
            }

            Step.PASSWORD -> {
                val hide = if (showPass) VisualTransformation.None else PasswordVisualTransformation()
                OutlinedTextField(
                    value = pass1,
                    onValueChange = { pass1 = it; problem = "" },
                    label = { Text("пароль") },
                    singleLine = true,
                    visualTransformation = hide,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = pass2,
                    onValueChange = { pass2 = it; problem = "" },
                    label = { Text("ещё раз") },
                    singleLine = true,
                    visualTransformation = hide,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                // Пароль вводится дважды и вслепую — сверить его глазами иначе нельзя, а
                // ошибиться в нём означает потерять доступ к обеим ссылкам сразу.
                Row(
                    Modifier.fillMaxWidth().padding(top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = showPass, onCheckedChange = { showPass = it })
                    Text("показать пароль", Modifier.padding(start = 8.dp), fontSize = 14.sp)
                }
                Hint("Пароль шифрует обе ссылки. Он защищает их при передаче: перехваченная" +
                    " ссылка без пароля бесполезна. В самой сети пароль не участвует — узлы" +
                    " проверяют подпись и про него не знают ничего.")

                Button(
                    onClick = {
                        when {
                            pass1.length < 8 -> problem = "пароль короче восьми знаков"
                            pass1 != pass2 -> problem = "пароли не совпали"
                            else -> {
                                busy = true
                                problem = ""
                                scope.launch {
                                    val res = withContext(Dispatchers.IO) {
                                        runCatching {
                                            Core.createNetwork(name.trim(), pass1,
                                                up.toIntOrNull() ?: 0,
                                                down.toIntOrNull() ?: 0,
                                                mesh.toIntOrNull() ?: 0)
                                        }
                                    }
                                    busy = false
                                    res.onSuccess { created ->
                                        genesis = created.genesis
                                        // Ссылок пока нет: их не из чего собрать, пока в сети
                                        // нет ни одного узла. Дальше — развёртывание.
                                        step = Step.DEPLOY
                                    }.onFailure { problem = it.message ?: "сеть не создалась" }
                                }
                            }
                        }
                    },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                ) {
                    if (busy) {
                        CircularProgressIndicator(Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                        Text("создаю…")
                    } else {
                        Text("Создать сеть")
                    }
                }
                OutlinedButton(
                    onClick = { step = Step.PARAMS },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                ) { Text("Назад") }
            }

            Step.LINKS -> {
                LaunchedEffect(Unit) {
                    if (working.isEmpty()) {
                        busy = true
                        val res = withContext(Dispatchers.IO) {
                            runCatching { Core.issueOwnerBundles(pass1) }
                        }
                        busy = false
                        res.onSuccess { issued ->
                            working = issued.working
                            spare = issued.spare
                            // Рабочая ссылка сразу становится своей: с этой минуты приложение —
                            // клиент собственной сети, и в ссылке уже есть куда идти.
                            prefs.setNetwork(issued.working, pass1)
                        }.onFailure { problem = it.message ?: "ссылки не собрались" }
                    }
                }

                Text("Узел в сети: $adopted", fontSize = 13.sp, color = Green)
                Text("Отпечаток сети", fontSize = 13.sp, color = Green,
                    modifier = Modifier.padding(top = 12.dp))
                Text(genesis, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(bottom = 12.dp))

                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.padding(end = 12.dp), strokeWidth = 2.dp)
                        Text("собираю ссылки…", fontSize = 14.sp)
                    }
                } else if (working.isNotEmpty()) {
                    LinkBlock(
                        title = "Рабочая ссылка",
                        hint = "Уже сохранена в этом приложении. Пригодится, чтобы вернуть" +
                            " управление после переустановки.",
                        value = working,
                        ctx = ctx,
                    )
                    LinkBlock(
                        title = "Запасная ссылка",
                        hint = "Унеси туда, куда не дотянется ни этот телефон, ни переписка. Это" +
                            " единственный способ вернуть управление, если рабочая пропадёт." +
                            " С устройства она уже стёрта.",
                        value = spare,
                        ctx = ctx,
                    )
                    Hint("Обе ссылки несут узлы сети и потолки скорости — по ним клиент найдёт," +
                        " куда подключаться, даже на чистом устройстве.")

                    Button(
                        onClick = { step = Step.CONFIRM },
                        modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                    ) { Text("Сохранил обе") }
                }
            }

            Step.CONFIRM -> ConfirmStep(
                onConfirmed = onDone,
                onCopyAgain = {
                    // Обе разом: буфер один, а нужны обе, и человек на этом экране уже понял,
                    // что сохранил не всё.
                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText(
                        "ссылки владельца",
                        "Рабочая ссылка:\n$working\n\nЗапасная ссылка:\n$spare",
                    ))
                },
            )

            Step.DEPLOY -> {
                // Ключ собран из этих двух полей. Правка любого из них его обесценивает: строка
                // на экране осталась бы прежней, а человек унёс бы её на сервер и развернул узел
                // не с тем именем и не на том домене — ровно так и вышло при первой обкатке.
                val stale = deployKey.isNotEmpty() && keyFrom != "${nodeId.trim()}|${domain.trim()}"

                OutlinedTextField(
                    value = nodeId,
                    onValueChange = { nodeId = it; problem = "" },
                    label = { Text("имя узла") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = domain,
                    onValueChange = { domain = it; problem = "" },
                    label = { Text("домен узла") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                Hint("Домен обязан указывать на этот сервер: узел сам выпустит на него" +
                    " сертификат при первом запуске. Роль первого узла не спрашивается — он" +
                    " входной.")

                if (deployKey.isEmpty() || stale) {
                    if (stale) {
                        Text(
                            "Поля изменились — прежний ключ больше не годится. Собери заново.",
                            fontSize = 12.sp,
                            color = Amber,
                            modifier = Modifier.padding(top = 12.dp),
                        )
                    }
                    Button(
                        onClick = {
                            when {
                                nodeId.isBlank() -> problem = "введи имя узла"
                                domain.isBlank() -> problem = "введи домен"
                                else -> runCatching {
                                    Core.deployKey(nodeId.trim(), domain.trim(), "ingress")
                                }.onSuccess {
                                    deployKey = it
                                    keyFrom = "${nodeId.trim()}|${domain.trim()}"
                                    code = ""
                                }.onFailure { problem = it.message ?: "ключ не собрался" }
                            }
                        },
                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                    ) { Text(if (stale) "Собрать заново" else "Собрать ключ развёртывания") }
                    OutlinedButton(
                        onClick = { step = Step.PARAMS },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    ) { Text("Назад к параметрам сети") }
                } else {
                    LinkBlock(
                        title = "Ключ развёртывания",
                        hint = "Запусти на сервере скрипт развёртывания и дай ему эту строку." +
                            " Секретов в ней нет: отпечаток — хеш публичной записи, остальное" +
                            " ты только что ввёл сам.",
                        value = deployKey,
                        ctx = ctx,
                    )

                    Header("Код узла")
                    OutlinedTextField(
                        value = code,
                        onValueChange = { code = it.uppercase(); problem = "" },
                        label = { Text("восемь знаков из терминала") },
                        placeholder = { Text("3F7K-92QW") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Hint("Скрипт напечатает его на сервере, когда узел поднимется. Сертификат" +
                        " домена доказывает только владение доменом: перехвативший его на пять" +
                        " минут ответил бы своим ключом, и в журнал попал бы чужой узел. Код" +
                        " напечатан там, куда перехватившему не заглянуть.")

                    Button(
                        onClick = {
                            if (code.filter { it.isLetterOrDigit() }.length < 8) {
                                problem = "код — восемь знаков"
                            } else {
                                problem = ""
                                step = Step.WAITING
                            }
                        },
                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                    ) { Text("Узел поднят — включить в сеть") }
                    OutlinedButton(
                        onClick = { deployKey = ""; code = ""; problem = "" },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    ) { Text("Изменить имя или домен") }
                }
            }

            Step.WAITING -> WaitingStep(
                domain = domain.trim(),
                code = code,
                onProblem = { problem = it },
                onAdopted = { adopted = it; step = Step.LINKS },
                onGiveUp = { step = Step.DEPLOY },
            )

        }
    }
}

/**
 * Подтверждение с таймером (решение 007 §3, шаг 4).
 *
 * Пятнадцать секунд, в течение которых кнопка не нажимается. Это не придирка к человеку:
 * запасная ссылка — единственное, что вернёт управление сетью, и пролистнуть этот экран не
 * читая ничего не стоит. Потерять её нельзя, а восстановления нет и не будет (§2.2).
 */
@Composable
private fun ConfirmStep(onConfirmed: () -> Unit, onCopyAgain: () -> Unit) {
    var left by remember { mutableStateOf(15) }
    var checked by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        while (left > 0) {
            delay(1000)
            left--
        }
    }

    Text("Обе ссылки сохранены?", fontSize = 17.sp)
    Hint("Если потеряны обе, управление сетью не вернуть никак. Узлы и трафик останутся, а" +
        " история — клиенты, лимиты, расход — нет: придётся начинать журнал заново и выдавать" +
        " всем новые ссылки.\n\nВосстановления нет намеренно. Любой способ «вернуть управление" +
        " без ключа» — это второй вход, и он же второй способ управление украсть.")

    Row(
        Modifier.fillMaxWidth().padding(top = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = { checked = it }, enabled = left == 0)
        Text(
            "сохранил, понимаю последствия",
            Modifier.padding(start = 8.dp),
            fontSize = 14.sp,
            color = if (left == 0) MaterialTheme.colorScheme.onSurface else Grey,
        )
    }
    if (left > 0) {
        Text("ещё $left с", fontSize = 12.sp, color = Amber, modifier = Modifier.padding(top = 4.dp))
    }

    Button(
        onClick = onConfirmed,
        enabled = checked && left == 0,
        modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
    ) { Text("Готово") }

    // Назад отсюда пути нет: узел уже в сети, клиент подключён, и «отменить» тут нечего. А вот
    // сохранить ссылки заново человек может захотеть — на этом экране он как раз и понимает,
    // что скопировал не всё.
    OutlinedButton(
        onClick = { onCopyAgain(); copied = true },
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) { Text(if (copied) "Обе ссылки в буфере" else "Нет, скопировать ещё раз") }
    Hint("Обе разом, с подписями. Дальше этого экрана ссылки больше не показываются: запасной" +
        " ключ с устройства уже стёрт.")
}

/**
 * Ожидание узла (решение 007 §3, шаг 7).
 *
 * Приложение стучится к домену раз в несколько секунд, пока узел не поднимется и не назовёт
 * себя. Ждать приходится долго: скрипту нужно поставить пакеты, а узлу — выпустить сертификат
 * через ACME, и это минуты, а не секунды.
 */
@Composable
private fun WaitingStep(
    domain: String,
    code: String,
    onProblem: (String) -> Unit,
    onAdopted: (String) -> Unit,
    onGiveUp: () -> Unit,
) {
    var tries by remember { mutableStateOf(0) }
    var last by remember { mutableStateOf("") }
    var stopped by remember { mutableStateOf(false) }

    LaunchedEffect(domain) {
        while (true) {
            tries++
            val res = withContext(Dispatchers.IO) { runCatching { Core.adoptNode(domain, "ingress", code) } }
            res.onSuccess { got ->
                if (got.adopted) {
                    onAdopted("${got.id} · ${got.domain}")
                    return@LaunchedEffect
                }
                // Код не совпал. Повторять нельзя: код считается из ключа узла, ключ у него
                // один, и следующая попытка даст ровно то же. А если на том конце подделка,
                // каждый повтор дарит ей ещё одну попытку угадать.
                if (got.wrongCode) {
                    stopped = true
                    onProblem("Узел на том конце назвался другим кодом. Либо код введён с" +
                        " ошибкой, либо это не твой узел — проверь, что напечатал скрипт.")
                    return@LaunchedEffect
                }
            }
            last = res.exceptionOrNull()?.message ?: "узел молчит"
            delay(5000)
        }
    }

    if (!stopped) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.padding(end = 12.dp), strokeWidth = 2.dp)
            Text("Жду узел $domain", fontSize = 15.sp)
        }
        Text("попыток $tries", fontSize = 12.sp, color = Grey, modifier = Modifier.padding(top = 8.dp))
        if (last.isNotEmpty()) {
            Text(last, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(top = 4.dp))
        }
        Hint("Узел поднимется не мгновенно: скрипт ставит пакеты, а сертификат выпускается" +
            " через ACME. Приложение спросит его имя и ключ, сверит код, подпишет запись и" +
            " отдаст журнал.")
    }

    OutlinedButton(
        onClick = { onProblem(""); onGiveUp() },
        modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
    ) { Text(if (stopped) "Назад" else "Прервать") }
}

/** Строка, которую человек должен унести целиком: показ и копирование. */
@Composable
private fun LinkBlock(title: String, hint: String, value: String, ctx: Context) {
    var copied by remember { mutableStateOf(false) }

    Text(title, fontSize = 14.sp, color = Green, modifier = Modifier.padding(top = 16.dp))
    Text(
        value,
        fontSize = 10.sp,
        color = Grey,
        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
    )
    OutlinedButton(
        onClick = {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText(title, value))
            copied = true
        },
        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
    ) { Text(if (copied) "скопировано" else "Скопировать") }
    Hint(hint)
}

@Composable
private fun Mbps(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = { v -> onChange(v.filter { it.isDigit() }) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    )
}

private fun stepHint(step: Step): String = when (step) {
    Step.PARAMS -> "Шаг 1 из 5 · имя сети и потолки"
    Step.PASSWORD -> "Шаг 2 из 5 · пароль на ссылки"
    Step.DEPLOY -> "Шаг 3 из 5 · первый узел"
    Step.WAITING -> "Шаг 4 из 5 · включение узла"
    Step.LINKS -> "Шаг 5 из 5 · две ссылки владельца"
    Step.CONFIRM -> "Шаг 5 из 5 · подтверждение"
}

@Composable
private fun Header(title: String) {
    Text(title, fontSize = 15.sp, color = Green, modifier = Modifier.padding(top = 20.dp, bottom = 4.dp))
}

@Composable
private fun Hint(text: String) {
    Text(text, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(top = 4.dp))
}
