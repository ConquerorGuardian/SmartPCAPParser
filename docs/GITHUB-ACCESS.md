# Публикация на GitHub, если github.com не открывается

Три рабочих пути. Все проверены на уровне сети с этой машины: DNS и TCP до
`github.com:443` работают, SSH до `ssh.github.com:443` доходит до проверки
ключа.

## 1. Быстрый обход: Cloudflare WARP (бесплатно)

Ставится как обычное приложение, включает туннель и обычно пробивает
блокировки провайдера, не меняя DNS:

1. https://1.1.1.1/ → скачать для Windows → установить.
2. Включить WARP, проверить `https://github.com`.
3. Не помогло — тот же шаг с обычным VPN или мобильным интернетом
   (телефон как точка доступа часто обходит фильтрацию провайдера).

## 2. Git через SSH-порт 443

HTTPS иногда режут, а SSH на 443 проходит. Один раз настроить ключ:

```powershell
ssh-keygen -t ed25519 -C "you@example.com"      # Enter, Enter
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub | Set-Clipboard
```

Ключ вставить на GitHub: **Settings → SSH and GPG keys → New SSH key**.
Затем remote в SSH-виде:

```powershell
git remote set-url origin ssh://git@ssh.github.com:443/Whitemoneydealer/SmartPCAPParser.git
ssh -T -p 443 git@ssh.github.com      # должно ответить "Hi <ник>!"
git push -u origin main
git push origin v1.9.1
```

Если `~/.ssh/config` уже есть, достаточно:

```
Host github.com
    HostName ssh.github.com
    Port 443
    User git
```

## 3. Отложенная публикация: bundle-файл

Если интернета до GitHub нет вообще, проект переносится одним файлом —
в нём вся история git:

```bash
python tools/backup.py                 # обычный архив
git bundle create SmartPCAPParser.bundle --all
```

Дальше на любой машине/телефоне с доступом:

```bash
git clone SmartPCAPParser.bundle SmartPCAPParser
cd SmartPCAPParser
git remote add origin https://github.com/Whitemoneydealer/SmartPCAPParser.git
git push -u origin main --tags
```

## Что проверить, если «не пускает» в аккаунт

- Пароль не подходит → восстановление по e-mail, старый пароль мог истечь.
- Просит 2FA → код из приложения-аутентификатора или резервный код.
- «Your account has been flagged» → письмо в Support, обычно отвечают за день.
- Бесконечная капча → отключить VPN на время входа, потом включить снова.
- `git push` просит пароль → нужен **Personal Access Token**
  (Settings → Developer settings → Tokens, права `Contents: read/write`),
  обычный пароль GitHub не принимает.

## Что делать, если совсем никак

Скажите — соберу bundle, exe и папку с инструкцией в один архив
`SmartPCAPParser-publish.zip`, который можно отнести на машину с доступом
(или отправить тому, у кого он есть) и опубликовать оттуда.
