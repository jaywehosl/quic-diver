package ru.qdiver.client

import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.VerticalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.activity.compose.BackHandler
import kotlinx.coroutines.launch

/**
 * Раскладка экранов: главный в середине, остальные по сторонам.
 *
 * ```
 *              [ Управление ]        ← вверх, только владельцу
 *                    ↕
 * [Маршрутизация] ← [ГЛАВНЫЙ] → [Настройки]
 *                    ↕
 *              [   Журнал   ]        ← вниз, если включён
 * ```
 *
 * # Почему вертикаль работает только с главного
 *
 * Иначе жесты спорят. На маршрутизации и в настройках свои списки с прокруткой, и вертикальный
 * свайп там означает «пролистать содержимое», а не «уйти на другой экран». Палец редко идёт
 * строго вертикально, поэтому диагональ уводила бы человека с экрана посреди чтения.
 *
 * Сделано это одной строкой: вертикальному пейджеру прокрутка разрешена, только когда
 * горизонтальный стоит на главном.
 *
 * # Почему не четыре отдельных экрана с кнопками
 *
 * Пейджер даёт то, чего не даёт смена состояния: содержимое соседней страницы видно уже во
 * время движения пальца. Человек понимает, куда идёт, не отпуская экран, и может передумать.
 */

/** Горизонтальные страницы. Главная посередине — от неё пляшут остальные. */
private const val PAGE_ROUTING = 0
private const val PAGE_MAIN = 1
private const val PAGE_SETTINGS = 2
private const val HORIZONTAL_PAGES = 3

@Composable
fun Shell(
    prefs: Prefs,
    journal: Journal,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onWiped: () -> Unit,
) {
    // Владелец и подробный журнал решают, сколько страниц по вертикали. Спрашивается один раз
    // на открытие: ключ владельца не появляется сам собой, а галка журнала требует перехода в
    // настройки — то есть перерисовки в любом случае.
    val owner = remember { Core.owner() }
    var verbose by remember { mutableStateOf(prefs.verbose) }

    val hasControl = owner.owner
    val hasLog = verbose

    // Вертикаль собирается из того, что доступно: страницы, которой нет, не должно быть и в
    // списке — иначе свайп упирался бы в пустой экран.
    val vertical = buildList {
        if (hasControl) add(VerticalPage.CONTROL)
        add(VerticalPage.MAIN)
        if (hasLog) add(VerticalPage.LOG)
    }
    val mainIndex = vertical.indexOf(VerticalPage.MAIN)

    val horizontalState = rememberPagerState(initialPage = PAGE_MAIN) { HORIZONTAL_PAGES }
    val verticalState = rememberPagerState(initialPage = mainIndex) { vertical.size }
    val scope = rememberCoroutineScope()

    val onMain = horizontalState.currentPage == PAGE_MAIN
    val atCenter = onMain && verticalState.currentPage == mainIndex

    // «Назад» возвращает на главный, а не закрывает приложение: человек ушёл на страницу
    // свайпом, и обратный путь должен быть таким же коротким.
    BackHandler(enabled = !atCenter) {
        scope.launch {
            if (verticalState.currentPage != mainIndex) verticalState.animateScrollToPage(mainIndex)
            else horizontalState.animateScrollToPage(PAGE_MAIN)
        }
    }

    // Галка подробного журнала могла поменяться в настройках — страница появляется и исчезает.
    LaunchedEffect(horizontalState.currentPage) {
        if (horizontalState.currentPage == PAGE_MAIN) verbose = prefs.verbose
    }

    VerticalPager(
        state = verticalState,
        userScrollEnabled = onMain,
        modifier = Modifier.fillMaxSize(),
    ) { page ->
        when (vertical[page]) {
            VerticalPage.CONTROL -> ControlScreen(
                onBack = { scope.launch { verticalState.animateScrollToPage(mainIndex) } },
            )

            VerticalPage.LOG -> JournalScreen(
                journal = journal,
                onBack = { scope.launch { verticalState.animateScrollToPage(mainIndex) } },
            )

            VerticalPage.MAIN -> HorizontalPager(
                state = horizontalState,
                modifier = Modifier.fillMaxSize(),
            ) { h ->
                when (h) {
                    PAGE_ROUTING -> RoutingScreen(prefs) {
                        scope.launch { horizontalState.animateScrollToPage(PAGE_MAIN) }
                    }
                    PAGE_SETTINGS -> SettingsScreen(
                        prefs = prefs,
                        onBack = { scope.launch { horizontalState.animateScrollToPage(PAGE_MAIN) } },
                        onWiped = onWiped,
                    )
                    else -> Box(Modifier.fillMaxSize()) {
                        MainScreen(
                            prefs = prefs,
                            onConnect = onConnect,
                            onDisconnect = onDisconnect,
                            hasControl = hasControl,
                            hasLog = hasLog,
                        )
                    }
                }
            }
        }
    }
}

/** Что лежит по вертикали. Главная всегда есть, остальные — по обстоятельствам. */
private enum class VerticalPage { CONTROL, MAIN, LOG }

/** Ориентация нужна вызывающему коду жестов; вынесена, чтобы не тянуть импорт по файлам. */
internal val verticalOrientation = Orientation.Vertical
