package ru.qdiver.client

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Color

/**
 * Цвета.
 *
 * Своя схема, а не динамическая от системы: приложение говорит цветом о вещах, которые нельзя
 * перекрасить под обои, — зелёное значит «идёт напрямую», синее «через выход», красное
 * «закрыто». Пусть на всех устройствах это будет одно и то же.
 *
 * У каждого такого цвета две версии: на светлом фоне нужен тёмный оттенок, на тёмном —
 * светлый. Один цвет на оба случая либо теряется, либо режет глаза.
 */
private val GreenLight = Color(0xFF2E7D32)
private val GreenDark = Color(0xFF81C784)
private val BlueLight = Color(0xFF1565C0)
private val BlueDark = Color(0xFF64B5F6)
private val RedLight = Color(0xFFC62828)
private val RedDark = Color(0xFFE57373)
private val AmberLight = Color(0xFFEF6C00)
private val AmberDark = Color(0xFFFFB74D)
private val GreyLight = Color(0xFF757575)
private val GreyDark = Color(0xFFA0A0A0)

/** Цвета смысла. Читаются из темы, поэтому сами знают, светло вокруг или темно. */
val Green: Color @Composable @ReadOnlyComposable get() = pick(GreenLight, GreenDark)
val Blue: Color @Composable @ReadOnlyComposable get() = pick(BlueLight, BlueDark)
val Red: Color @Composable @ReadOnlyComposable get() = pick(RedLight, RedDark)
val Amber: Color @Composable @ReadOnlyComposable get() = pick(AmberLight, AmberDark)
val Grey: Color @Composable @ReadOnlyComposable get() = pick(GreyLight, GreyDark)

@Composable
@ReadOnlyComposable
private fun pick(light: Color, dark: Color): Color =
    if (MaterialTheme.colorScheme.background.luminance() < 0.5f) dark else light

private fun Color.luminance(): Float = 0.299f * red + 0.587f * green + 0.114f * blue

@Composable
fun qdiverColors(dark: Boolean = isSystemInDarkTheme()) = if (dark) {
    darkColorScheme(primary = BlueDark, secondary = GreenDark, error = RedDark)
} else {
    lightColorScheme(primary = BlueLight, secondary = GreenLight, error = RedLight)
}

/** Цвет действия правила: один и тот же везде, где это действие показывается. */
@Composable
fun colorOf(act: Act): Color = when (act) {
    Act.DIRECT -> Green
    Act.EGRESS -> Blue
    Act.BLOCK -> Red
}
