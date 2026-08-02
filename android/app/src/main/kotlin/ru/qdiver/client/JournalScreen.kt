package ru.qdiver.client

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Журнал событий отдельным экраном.
 *
 * Раньше он жил внизу главного, вперемешку с состоянием, и занимал место у того, ради чего
 * приложение открывают. При этом нужен он редко — когда что-то повело себя непонятно.
 *
 * Показывается, только если включён подробный журнал: человеку, у которого всё работает,
 * страница с техническими строками не нужна вовсе.
 */
@Composable
fun JournalScreen(journal: Journal, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Журнал", fontSize = 22.sp, modifier = Modifier.weight(1f))
            Text("${journal.lines.size} строк", fontSize = 12.sp, color = Grey)
        }

        if (journal.lines.isEmpty()) {
            Text(
                "Пусто. Строки появляются при подключении, смене правил и обновлении сети.",
                fontSize = 12.sp,
                color = Grey,
                modifier = Modifier.padding(top = 12.dp),
            )
        }

        LazyColumn(Modifier.fillMaxWidth().weight(1f).padding(top = 12.dp)) {
            // Свежее сверху: смотрят сюда сразу после того, как что-то случилось.
            items(journal.lines.asReversed()) { line ->
                Text(line, fontSize = 11.sp, color = Grey, modifier = Modifier.padding(vertical = 2.dp))
            }
        }

        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text("Назад")
        }
    }
}
