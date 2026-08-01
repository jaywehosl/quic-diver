package ru.qdiver.client

import androidx.compose.runtime.mutableStateListOf

/**
 * Журнал: то, что ядро рассказывает о себе.
 *
 * Список наблюдаемый — экран перерисовывается сам, когда строка приходит из чужого потока.
 * Держится в объекте, а не в экране, чтобы пережить поворот и уход в маршрутизацию: строку,
 * появившуюся, пока человек был на другом экране, он потом всё равно ищет.
 */
object Journal {

    private const val MAX = 400

    val lines = mutableStateListOf<String>()

    /** post зовётся из чужих потоков — Compose это переживает, список потокобезопасен. */
    fun post(line: String) {
        synchronized(lines) {
            lines.add(line)
            while (lines.size > MAX) lines.removeAt(0)
        }
    }

    fun clear() = synchronized(lines) { lines.clear() }
}
