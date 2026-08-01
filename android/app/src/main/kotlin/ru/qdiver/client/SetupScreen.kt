package ru.qdiver.client

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Первый экран: ввод ссылки на сеть.
 *
 * Пока сети нет, показывать нечего и настраивать нечего — ни узлов, ни правил, ни лимитов.
 * Поэтому приложение начинается отсюда, а не с главного экрана с неработающими кнопками.
 *
 * Ссылка приходит от того, кто держит сеть, и содержит приватный ключ клиента. Набирать её
 * руками не должен никто: обычный путь — нажать её в переписке, и тогда система приведёт сюда
 * с уже подставленным текстом.
 */
@Composable
fun SetupScreen(prefs: Prefs, onDone: () -> Unit, onCreate: () -> Unit) {
    var bundle by remember { mutableStateOf(prefs.bundle) }
    var password by remember { mutableStateOf(prefs.password) }
    var problem by remember { mutableStateOf("") }
    var owner by remember { mutableStateOf(Core.owner()) }
    var confirmWipe by remember { mutableStateOf(false) }
    var showPass by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "Вставь ссылку на сеть",
            fontSize = 22.sp,
            modifier = Modifier.padding(top = 40.dp),
        )
        Text(
            "Ссылка вида qdiver://… приходит от того, кто держит сеть. В ней узлы, параметры и" +
                " твой ключ — обращайся с ней как с паролем.",
            fontSize = 13.sp,
            color = Grey,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
        )

        OutlinedTextField(
            value = bundle,
            onValueChange = { bundle = it; problem = "" },
            placeholder = { Text("qdiver://…") },
            minLines = 3,
            maxLines = 5,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            placeholder = { Text("пароль ссылки, если он есть") },
            singleLine = true,
            visualTransformation =
                if (showPass) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions.Default,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Row(
            Modifier.fillMaxWidth().padding(top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = showPass, onCheckedChange = { showPass = it })
            Text("показать пароль", Modifier.padding(start = 8.dp), fontSize = 13.sp)
        }

        if (problem.isNotEmpty()) {
            Text(problem, fontSize = 13.sp, color = Red, modifier = Modifier.padding(top = 8.dp))
        }

        Button(
            onClick = {
                val value = bundle.trim()
                when {
                    value.isEmpty() -> problem = "вставь ссылку"
                    !value.startsWith("qdiver://") -> problem = "ссылка должна начинаться с qdiver://"
                    else -> {
                        prefs.setNetwork(value, password)
                        onDone()
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
        ) { Text("Продолжить") }

        // Своя сеть — второй, редкий путь. Кнопку видит каждый, и это безвредно: посторонний
        // создаст свою сеть, с другими ключами и другим отпечатком, и к чужим узлам она не
        // подойдёт. Сеть без единого узла вреда не приносит никому (решение 007 §2).
        Text(
            "или создать свою сеть",
            fontSize = 13.sp,
            color = Blue,
            modifier = Modifier.clickable(onClick = onCreate).padding(top = 24.dp, bottom = 4.dp),
        )
        Text(
            "Нужен сервер: Linux, домен и открытые порты 80 и 443.",
            fontSize = 11.sp,
            color = Grey,
            textAlign = TextAlign.Center,
        )

        // Сеть на устройстве уже есть, а человек снова на первом экране — значит прошлая
        // попытка оборвалась на середине. Создать вторую поверх первой нельзя: это стёрло бы
        // ключи от первой без всякой возможности их вернуть. Сброс — единственный выход, и
        // искать его в системных настройках приложения человек не должен.
        if (owner.owner) {
            Text(
                "На устройстве уже есть сеть ${owner.network}: узлов ${owner.nodes}," +
                    " записей ${owner.records}",
                fontSize = 12.sp,
                color = Amber,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 24.dp),
            )
            OutlinedButton(
                onClick = { confirmWipe = true },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            ) { Text("Стереть её и начать заново") }
            Text(
                "Ключи, журнал и все настройки будут удалены. Если ссылки владельца не" +
                    " сохранены — управление той сетью не вернуть никак.",
                fontSize = 11.sp,
                color = Grey,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }

    if (confirmWipe) {
        AlertDialog(
            onDismissRequest = { confirmWipe = false },
            title = { Text("Стереть сеть ${owner.network}?") },
            text = {
                Text("Ключи владельца, журнал и настройки будут удалены с этого устройства." +
                    " Вернуть управление можно будет только запасной ссылкой, если она" +
                    " сохранена. Узлы, уже стоящие на серверах, останутся без владельца.")
            },
            confirmButton = {
                TextButton(onClick = {
                    prefs.wipe()
                    Core.wipeOwner()
                    confirmWipe = false
                    bundle = ""
                    password = ""
                    owner = Owner()
                }) { Text("Стереть") }
            },
            dismissButton = { TextButton(onClick = { confirmWipe = false }) { Text("Отмена") } },
        )
    }
}
