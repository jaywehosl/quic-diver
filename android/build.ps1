# Сборка APK.
#
# Два шага: gomobile собирает ядро в app/libs/qdiver.aar, Gradle собирает вокруг него
# приложение. Своя сборка на aapt2 и d8 здесь была, пока приложение состояло из одного экрана;
# с появлением списков и жестов она перестала окупаться — свайпы с анимацией, отзывчивый
# список и диалоги в стандартном наборе есть готовыми.

# Continue, а не Stop: PowerShell 5.1 считает ошибкой любую строку, которую внешняя программа
# написала в поток ошибок, — а Gradle пишет туда обычные предупреждения. Судим по коду
# возврата, и он проверяется после каждого вызова.
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA\Android\Sdk" }
$ndk = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { "$sdk\ndk\27.2.12479018" }
$gradle = if ($env:GRADLE_HOME) { "$env:GRADLE_HOME\bin\gradle.bat" } else { "$env:LOCALAPPDATA\gradle\gradle-8.14\bin\gradle.bat" }

if (-not (Test-Path $gradle)) {
    throw "Gradle не найден: $gradle. Скачать: https://services.gradle.org/distributions/gradle-8.14-bin.zip"
}

$abi = if ($env:QD_ABI) { $env:QD_ABI } else { 'arm64-v8a' }
$goarch = @{ 'arm64-v8a' = 'arm64'; 'armeabi-v7a' = 'arm'; 'x86_64' = 'amd64' }[$abi]

$aar = "$PSScriptRoot\app\libs\qdiver.aar"

# gomobile пересобирает ядро целиком при каждом вызове — своего кеша у него нет, и это
# несколько минут на ровном месте. Правки в экранах Go-кода не касаются вовсе, поэтому
# сравниваем времена: .aar новее всех исходников — пересобирать нечего.
$needCore = $true
if ((Test-Path $aar) -and -not $env:QD_FORCE_CORE) {
    $aarTime = (Get-Item $aar).LastWriteTimeUtc
    $newest = Get-ChildItem "$root\internal", "$root\mobile", "$root\third_party" -Recurse -File -Include *.go, go.mod, go.sum -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($newest -and $newest.LastWriteTimeUtc -lt $aarTime) {
        $needCore = $false
        Write-Host "== ядро не менялось, беру готовое (пересобрать: `$env:QD_FORCE_CORE=1) =="
    }
}

if ($needCore) {
    Write-Host "== ядро (gomobile bind, android/$goarch) =="
    $env:PATH = "$env:USERPROFILE\go\bin;$env:PATH"
    $env:ANDROID_HOME = $sdk
    $env:ANDROID_NDK_HOME = $ndk
    # gomobile переносит наши комментарии в javadoc и зовёт javac без -encoding. На русской
    # Windows тот берёт кодировку системы (1251) и падает на первом же символе, которого в ней
    # нет: «unmappable character (0x98)» — это второй байт буквы «И» в UTF-8.
    $env:JAVA_TOOL_OPTIONS = '-Dfile.encoding=UTF-8'

    Push-Location $root
    gomobile bind -target="android/$goarch" -androidapi 26 -o $aar ./mobile
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -ne 0) { throw "gomobile bind не собрал ядро" }
}

Write-Host "== приложение (gradle) =="
# Дальше JAVA_TOOL_OPTIONS не нужен: Gradle задаёт кодировку сам через gradle.properties, а
# лишняя переменная только сыплет «Picked up JAVA_TOOL_OPTIONS» в каждый вызов.
$env:JAVA_TOOL_OPTIONS = ''

# С демоном: он держит прогретую JVM между сборками, и повторный запуск выходит вдвое быстрее.
#
# Но запускается он через Start-Process с выводом в файлы, а не прямым вызовом. Причина в
# наследовании: демон — отдельный процесс, переживающий сборку на три часа, и при прямом вызове
# он получает наш поток вывода себе. Наш процесс закрывается, а труба остаётся открытой у
# демона, и тот, кто читает наш вывод, ждёт конца, которого не будет. Со стороны это выглядит
# как зависшая сборка: APK давно готов, java спит, никто ничего не делает.
$outLog = New-TemporaryFile
$errLog = New-TemporaryFile
$p = Start-Process -FilePath $gradle -ArgumentList @('-p', $PSScriptRoot, 'assembleRelease') `
    -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outLog -RedirectStandardError $errLog
Get-Content $outLog -ErrorAction SilentlyContinue
Get-Content $errLog -ErrorAction SilentlyContinue
Remove-Item $outLog, $errLog -Force -ErrorAction SilentlyContinue
if ($p.ExitCode -ne 0) { throw "gradle не собрал приложение" }

$apk = "$PSScriptRoot\app\build\outputs\apk\release\app-release.apk"
if (-not (Test-Path $apk)) { throw "APK не найден: $apk" }

$out = Join-Path $root 'build'
New-Item -ItemType Directory -Path $out -Force | Out-Null
Copy-Item $apk "$out\qdiver.apk" -Force
"{0}: {1:N1} МБ" -f "$out\qdiver.apk", ((Get-Item "$out\qdiver.apk").Length / 1MB)
