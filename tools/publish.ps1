# Публикация проекта на GitHub одной командой.
#
#   .\tools\publish.ps1 -Repo https://github.com/Whitemoneydealer/SmartPCAPParser.git
#   .\tools\publish.ps1 -Repo ssh://git@ssh.github.com:443/Whitemoneydealer/SmartPCAPParser.git
#
# Скрипт ничего не перезаписывает на сервере: только первый push и тег.

param(
    [Parameter(Mandatory = $true)]
    [string]$Repo,
    [string]$Tag = "v1.9.1",
    [switch]$SkipChecks
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail($message) {
    Write-Host ""
    Write-Host "НЕ ВЫПОЛНЕНО: $message" -ForegroundColor Red
    exit 1
}

Write-Host "Папка проекта: $root"

# 1. Репозиторий должен быть чистым: иначе на GitHub уедет недоделанное.
$dirty = git status --porcelain
if ($dirty -and -not $SkipChecks) {
    Write-Host $dirty
    Fail "есть незакоммиченные изменения. Сделайте git add -A; git commit -m '...' или запустите с -SkipChecks"
}

# 2. Проверка ветки и коммитов.
$branch = git rev-parse --abbrev-ref HEAD
$count = git rev-list --count HEAD
Write-Host "Ветка: $branch | коммитов: $count"
if ($branch -ne "main") {
    Write-Host "Переименовываю ветку в main: git branch -M main"
    git branch -M main
}

# 3. Сеть: до GitHub должен открываться TCP 443.
if (-not $SkipChecks) {
    $tcp = Test-NetConnection github.com -Port 443 -WarningAction SilentlyContinue
    if (-not $tcp.TcpTestSucceeded) {
        Fail "github.com:443 недоступен. Смотрите internal/GITHUB-ACCESS.md (WARP, VPN, мобильный интернет)"
    }
    Write-Host "Сеть до github.com:443 есть."
}

# 4. Remote.
$existing = git remote get-url origin 2>$null
if ($existing) {
    Write-Host "Меняю origin: $existing -> $Repo"
    git remote set-url origin $Repo
} else {
    git remote add origin $Repo
}

# 5. Push ветки и тега.
Write-Host "Отправляю ветку main..."
git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Fail "push не прошёл. Для HTTPS нужен Personal Access Token, для SSH нужен ключ (см. internal/GITHUB-ACCESS.md)"
}

Write-Host "Ставлю тег $Tag..."
$tagExists = git tag --list $Tag
if (-not $tagExists) {
    git tag -a $Tag -m "Smart PCAP Parser $($Tag.TrimStart('v'))"
} else {
    Write-Host "Тег $Tag уже есть."
}
git push origin $Tag
if ($LASTEXITCODE -ne 0) {
    Fail "тег не отправился"
}

Write-Host ""
Write-Host "Готово." -ForegroundColor Green
Write-Host "Тег запускает .github/workflows/build.yml: тесты, сборка exe, релиз."
Write-Host "Через несколько минут проверьте:"
Write-Host "  https://github.com/Whitemoneydealer/SmartPCAPParser/releases"
