package ru.qdiver.client

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

/**
 * Правила маршрутизации.
 *
 * Порядок секций на экране и есть порядок приоритета: сайты сильнее списков, списки сильнее
 * приложений. Объяснять это словами не нужно — человек видит, что выше.
 */
@Composable
fun RoutingScreen(prefs: Prefs, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val rules = remember { mutableStateListOf<Rule>().apply { addAll(Rule.parseAll(prefs.rules)) } }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val geo = remember { Core.geo() }

    var editing by remember { mutableStateOf<Int?>(null) }
    var adding by remember { mutableStateOf<Kind?>(null) }
    var confirmReset by remember { mutableStateOf(false) }

    fun save() {
        prefs.rules = Rule.toJson(rules)
        Core.applyRules(prefs.rules)?.let { Journal.post("правила не приняты: $it") }
    }

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad).padding(horizontal = 20.dp)) {
            item {
                Text("Маршрутизация", fontSize = 22.sp, modifier = Modifier.padding(top = 12.dp))
                Text(
                    text = if (geo.missing)
                        "Баз geosite и geoip нет — правила со списками не сработают."
                    else "Базы от ${geo.installed} · списков доменов ${geo.sites}, подсетей ${geo.ips}",
                    fontSize = 12.sp,
                    color = if (geo.missing) Amber else Grey,
                    modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                )
                Text(
                    "Свайп вправо — включить или выключить, влево — удалить. Тап — выбрать действие.",
                    fontSize = 11.sp,
                    color = Grey,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
            }

            Kind.entries.forEach { kind ->
                item(key = "head-$kind") {
                    Text(
                        kind.title,
                        fontSize = 15.sp,
                        color = Green,
                        modifier = Modifier.padding(top = 18.dp),
                    )
                    Text(kind.about, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(bottom = 4.dp))
                }

                val ofKind = rules.withIndex().filter { it.value.kind == kind }
                if (ofKind.isEmpty()) {
                    item(key = "empty-$kind") {
                        Text("пока пусто", fontSize = 12.sp, color = Grey, modifier = Modifier.padding(vertical = 6.dp))
                    }
                }

                items(ofKind, key = { "rule-${it.value.match}" }) { (index, rule) ->
                    RuleRow(
                        rule = rule,
                        geoMissing = geo.missing,
                        onTap = { editing = index },
                        onToggle = {
                            rules[index] = rule.copy(off = !rule.off)
                            save()
                        },
                        onDelete = {
                            val gone = rules.removeAt(index)
                            save()
                            scope.launch {
                                val res = snackbar.showSnackbar(
                                    message = "правило удалено",
                                    actionLabel = "вернуть",
                                )
                                if (res == SnackbarResult.ActionPerformed) {
                                    rules.add(index.coerceAtMost(rules.size), gone)
                                    save()
                                }
                            }
                        },
                    )
                    HorizontalDivider(color = Color(0x14000000))
                }

                item(key = "add-$kind") {
                    Text(
                        text = when (kind) {
                            Kind.SITE -> "+ добавить сайт"
                            Kind.LIST -> "+ добавить список"
                            Kind.APP -> "+ выбрать приложение"
                        },
                        fontSize = 13.sp,
                        color = Blue,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { adding = kind }
                            .padding(vertical = 10.dp),
                    )
                }
            }

            item {
                OutlinedButton(
                    onClick = { confirmReset = true },
                    modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                ) { Text("Сбросить правила") }
                Text(
                    "Стирает только правила. Сеть и остальные настройки останутся.",
                    fontSize = 11.sp,
                    color = Grey,
                    modifier = Modifier.padding(top = 4.dp, bottom = 24.dp),
                )
            }
        }
    }

    editing?.let { index ->
        if (index < rules.size) {
            ActionDialog(
                rule = rules[index],
                onDismiss = { editing = null },
                onPick = { act, force ->
                    rules[index] = rules[index].copy(action = act, force = force)
                    save()
                    editing = null
                },
            )
        } else {
            editing = null
        }
    }

    when (adding) {
        Kind.SITE -> SiteDialog(onDismiss = { adding = null }) { rule ->
            rules.add(0, rule)
            save()
            adding = null
        }
        Kind.LIST -> ListDialog(onDismiss = { adding = null }) { rule ->
            rules.add(rule)
            save()
            adding = null
        }
        Kind.APP -> AppDialog(onDismiss = { adding = null }) { rule ->
            rules.add(rule)
            save()
            adding = null
        }
        null -> Unit
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Сбросить правила?") },
            text = { Text("Все правила будут удалены. Сеть и остальные настройки останутся.") },
            confirmButton = {
                TextButton(onClick = {
                    rules.clear()
                    prefs.wipeRules()
                    Core.applyRules("")
                    confirmReset = false
                }) { Text("Сбросить") }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Отмена") } },
        )
    }
}

/**
 * Строка правила со свайпами.
 *
 * Вправо — включить или выключить, влево — удалить. Оба жеста показывают себя фоном и сдвигом:
 * движение без отклика человек считает промахом и повторяет, пока не сделает лишнего.
 */
@Composable
private fun RuleRow(
    rule: Rule,
    geoMissing: Boolean,
    onTap: () -> Unit,
    onToggle: () -> Unit,
    onDelete: () -> Unit,
) {
    val state = rememberSwipeToDismissBoxState(
        confirmValueChange = { value ->
            when (value) {
                SwipeToDismissBoxValue.StartToEnd -> {
                    onToggle()
                    // false: строка возвращается на место — она не исчезла, а сменила вид.
                    false
                }
                SwipeToDismissBoxValue.EndToStart -> {
                    onDelete()
                    true
                }
                else -> false
            }
        }
    )

    SwipeToDismissBox(
        state = state,
        backgroundContent = {
            val toEnd = state.dismissDirection == SwipeToDismissBoxValue.StartToEnd
            Row(
                Modifier
                    .fillMaxWidth()
                    .height(56.dp)
                    .background(if (toEnd) Green.copy(alpha = 0.15f) else Red.copy(alpha = 0.15f))
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = if (toEnd) Arrangement.Start else Arrangement.End,
            ) {
                if (toEnd) {
                    Text(if (rule.off) "включить" else "выключить", color = Green, fontSize = 13.sp)
                } else {
                    Icon(Icons.Default.Delete, contentDescription = "удалить", tint = Red)
                }
            }
        },
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface)
                .clickable(onClick = onTap)
                .padding(vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (rule.off) Grey else Green)
            )
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text(
                    rule.title,
                    fontSize = 14.sp,
                    color = if (rule.off) Grey else MaterialTheme.colorScheme.onSurface,
                )
                if (rule.needsGeo && geoMissing) {
                    Text("не сработает: нужны базы", fontSize = 10.sp, color = Amber)
                }
            }
            if (rule.force) {
                Icon(
                    Icons.Default.Lock,
                    contentDescription = "соблюдать всегда",
                    tint = Amber,
                    modifier = Modifier.size(14.dp).padding(end = 2.dp),
                )
            }
            Text(
                rule.action.words,
                fontSize = 12.sp,
                color = if (rule.off) Grey else colorOf(rule.action),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
    }
}

@Composable
private fun ActionDialog(rule: Rule, onDismiss: () -> Unit, onPick: (Act, Boolean) -> Unit) {
    var force by remember { mutableStateOf(rule.force) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(rule.title) },
        text = {
            Column {
                Act.entries.forEach { act ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onPick(act, force) }.padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = rule.action == act, onClick = { onPick(act, force) })
                        Text(act.words, Modifier.padding(start = 8.dp), color = colorOf(act))
                    }
                }
                HorizontalDivider(Modifier.padding(vertical = 8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = force, onCheckedChange = { force = it })
                    Text("соблюдать всегда", Modifier.padding(start = 8.dp), fontSize = 14.sp)
                }
                Text(
                    "Такое правило не перебивается никаким другим — даже правилом по имени сайта.",
                    fontSize = 11.sp,
                    color = Grey,
                )
            }
        },
        confirmButton = { TextButton(onClick = { onPick(rule.action, force) }) { Text("Готово") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun SiteDialog(onDismiss: () -> Unit, onAdd: (Rule) -> Unit) {
    var input by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Сайт") },
        text = {
            Column {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it; problem = "" },
                    singleLine = true,
                    placeholder = { Text("yandex.ru") },
                )
                Text(
                    "Домен и все его поддомены. Звёздочку писать не нужно — она уже подразумевается.",
                    fontSize = 11.sp,
                    color = Grey,
                    modifier = Modifier.padding(top = 6.dp),
                )
                if (problem.isNotEmpty()) {
                    Text(problem, fontSize = 12.sp, color = Red, modifier = Modifier.padding(top = 6.dp))
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val rule = Rule.site(input)
                if (rule == null) problem = "не похоже на имя сайта" else onAdd(rule)
            }) { Text("Добавить") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

/**
 * Выбор категории из баз.
 *
 * Имена показываются как есть: их полторы тысячи, они приходят из чужой базы и меняются
 * вместе с ней. Поэтому поиск, а не перевод и не отбор «главных».
 */
@Composable
private fun ListDialog(onDismiss: () -> Unit, onAdd: (Rule) -> Unit) {
    var isIP by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    val all = remember(isIP) { Core.lists(isIP) }
    val shown = remember(all, query) {
        if (query.isBlank()) all else all.filter { it.contains(query.trim().lowercase()) }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Список") },
        text = {
            Column {
                Row {
                    listOf(false to "сайты", true to "адреса").forEach { (ip, label) ->
                        Text(
                            label,
                            fontSize = 14.sp,
                            color = if (isIP == ip) Blue else Grey,
                            modifier = Modifier
                                .clickable { isIP = ip }
                                .padding(end = 20.dp, bottom = 8.dp),
                        )
                    }
                }
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    placeholder = { Text("поиск: ru, ads, google…") },
                    modifier = Modifier.fillMaxWidth(),
                )
                if (all.isEmpty()) {
                    Text(
                        "Базы не загружены — выбирать не из чего.",
                        fontSize = 12.sp,
                        color = Amber,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                LazyColumn(Modifier.height(320.dp).padding(top = 8.dp)) {
                    items(shown, key = { it }) { name ->
                        Text(
                            name,
                            fontSize = 14.sp,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onAdd(Rule.list(name, isIP)) }
                                .padding(vertical = 10.dp),
                        )
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

/**
 * Выбор установленного приложения.
 *
 * Показываются все, у кого есть выход в сеть, — а не только те, у кого система согласилась
 * отдать значок запуска. Прежний отбор по getLaunchIntentForPackage оставлял восемнадцать
 * строк из трёхсот: без QUERY_ALL_PACKAGES этот вызов молча возвращает null для чужих
 * пакетов, и список выглядел просто коротким.
 */
@Composable
private fun AppDialog(onDismiss: () -> Unit, onAdd: (Rule) -> Unit) {
    val ctx = LocalContext.current
    var query by remember { mutableStateOf("") }

    val apps = remember {
        val pm = ctx.packageManager
        pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { info ->
                info.packageName != ctx.packageName &&
                    pm.checkPermission(android.Manifest.permission.INTERNET, info.packageName) ==
                    PackageManager.PERMISSION_GRANTED
            }
            .map { it to pm.getApplicationLabel(it).toString() }
            .sortedBy { it.second.lowercase() }
    }
    val shown = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter { it.second.contains(query.trim(), ignoreCase = true) }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Приложение") },
        text = {
            Column {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    placeholder = { Text("поиск") },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    "Показаны приложения, у которых есть доступ в сеть: ${apps.size}",
                    fontSize = 11.sp,
                    color = Grey,
                    modifier = Modifier.padding(top = 6.dp),
                )
                LazyColumn(Modifier.height(320.dp).padding(top = 8.dp)) {
                    items(shown, key = { it.first.packageName }) { (info: ApplicationInfo, label) ->
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .clickable { onAdd(Rule.app(info.packageName, label)) }
                                .padding(vertical = 8.dp)
                        ) {
                            Text(label, fontSize = 14.sp)
                            Text(info.packageName, fontSize = 10.sp, color = Grey)
                        }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}
