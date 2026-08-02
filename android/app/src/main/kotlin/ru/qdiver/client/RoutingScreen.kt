package ru.qdiver.client

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
    var menu by remember { mutableStateOf<Int?>(null) }
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
                    "Тап — куда пускать. Долгий тап — включить, выключить, удалить, соблюдать всегда.",
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
                        onMenu = { menu = index },
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
                onPick = { act ->
                    rules[index] = rules[index].copy(action = act)
                    save()
                    editing = null
                },
            )
        } else {
            editing = null
        }
    }

    menu?.let { index ->
        if (index < rules.size) {
            val rule = rules[index]
            RuleMenu(
                rule = rule,
                onDismiss = { menu = null },
                onToggleForce = {
                    rules[index] = rule.copy(force = !rule.force)
                    save()
                    menu = null
                },
                onToggleOff = {
                    rules[index] = rule.copy(off = !rule.off)
                    save()
                    menu = null
                },
                onDelete = {
                    val gone = rules.removeAt(index)
                    save()
                    menu = null
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
        } else {
            menu = null
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
 * Строка правила: тап открывает редактор, долгий тап — меню действий.
 *
 * Свайпов здесь больше нет, и не по прихоти: горизонтальным свайпом теперь листаются экраны, а
 * два жеста в одном направлении спорят всегда — либо строка съест переход, либо переход съест
 * строку. Долгий тап ни с чем не конфликтует и вдобавок вмещает больше двух действий.
 */
// combinedClickable до сих пор помечен экспериментальным, хотя живёт в библиотеке годами и
// используется всюду. Пометка нужна только компилятору; поведение у него устоявшееся.
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun RuleRow(
    rule: Rule,
    geoMissing: Boolean,
    onTap: () -> Unit,
    onMenu: () -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .combinedClickable(onClick = onTap, onLongClick = onMenu)
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

/**
 * Меню действий по долгому тапу.
 *
 * «Соблюдать всегда» живёт только здесь, а не в редакторе и не при добавлении: свойство редкое,
 * и место ему рядом с остальными разовыми действиями, а не в каждом окне создания правила.
 */
@Composable
private fun RuleMenu(
    rule: Rule,
    onDismiss: () -> Unit,
    onToggleForce: () -> Unit,
    onToggleOff: () -> Unit,
    onDelete: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(rule.title) },
        text = {
            Column {
                Text(
                    if (rule.force) "Сейчас соблюдается всегда: не перебивается никаким другим правилом."
                    else "Обычное правило: сильнее его окажется правило по имени сайта.",
                    fontSize = 12.sp,
                    color = Grey,
                )
            }
        },
        confirmButton = {
            Column {
                TextButton(onClick = onToggleForce) {
                    Text(if (rule.force) "Снять «соблюдать всегда»" else "Соблюдать всегда")
                }
                TextButton(onClick = onToggleOff) {
                    Text(if (rule.off) "Включить" else "Выключить")
                }
                TextButton(onClick = onDelete) { Text("Удалить", color = Red) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Закрыть") } },
    )
}

/**
 * Редактор правила: куда пускать поток.
 *
 * «Соблюдать всегда» отсюда убрано намеренно — оно живёт в меню по долгому тапу. Свойство
 * редкое, а место в окне, которое открывают на каждое правило, стоит дорого: человек читает
 * лишнюю строку каждый раз, а пользуется ею раз в месяц.
 */
@Composable
private fun ActionDialog(rule: Rule, onDismiss: () -> Unit, onPick: (Act) -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(rule.title) },
        text = {
            Column {
                Act.entries.forEach { act ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onPick(act) }.padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = rule.action == act, onClick = { onPick(act) })
                        Text(act.words, Modifier.padding(start = 8.dp), color = colorOf(act))
                    }
                }
                if (rule.force) {
                    Text(
                        "Соблюдается всегда. Снять — долгим тапом по строке.",
                        fontSize = 11.sp,
                        color = Amber,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
        confirmButton = {},
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
