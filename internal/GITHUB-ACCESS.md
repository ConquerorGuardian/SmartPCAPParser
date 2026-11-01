# Если GitHub не открывается

Три способа, все проверены на этой машине: DNS и TCP до `github.com:443`
работают, SSH до `ssh.github.com:443` доходит до проверки ключа.

## 1. WARP

Бесплатно, ставится как обычное приложение и обычно пробивает фильтрацию
провайдера, не меняя DNS.

1. https://1.1.1.1/ , скачать для Windows, установить.
2. Включить WARP и открыть `https://github.com`.
3. Не помогло: обычный VPN или мобильный интернет с телефона как точка
   доступа.

## 2. Git через SSH на порт 443

HTTPS иногда режут, SSH на 443 обычно проходит. Ключ настраивается один раз:

```powershell
ssh-keygen -t ed25519 -C "you@example.com"      # Enter, Enter
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub | Set-Clipboard
```

Публичный ключ вставить на GitHub: Settings, SSH and GPG keys, New SSH key.
Дальше remote в SSH-виде:

```powershell
git remote set-url origin ssh://git@ssh.github.com:443/Whitemoneydealer/SmartPCAPParser.git
ssh -T -p 443 git@ssh.github.com      # должно ответить "Hi <ник>!"
git push -u origin main
git push origin v1.9.1
```

Если `~/.ssh/config` уже есть, достаточно добавить:

```
Host github.com
    HostName ssh.github.com
    Port 443
    User git
```

## 3. Bundle

Если до GitHub нет вообще ничего, проект переносится одним файлом, внутри
вся история git.

```bash
git bundle create SmartPCAPParser.bundle --all
```

На машине с доступом:

```bash
git clone SmartPCAPParser.bundle SmartPCAPParser
cd SmartPCAPParser
git remote add origin https://github.com/Whitemoneydealer/SmartPCAPParser.git
git push -u origin main --tags
```

Bundle можно отнести на флешке или отправить тому, у кого доступ есть.

## Если не пускает в аккаунт

- Пароль не подходит: восстановление по почте, старый пароль мог истечь.
- Просит 2FA: код из приложения-аутентификатора или резервный код.
- «Your account has been flagged»: письмо в Support, отвечают обычно за день.
- Бесконечная капча: выключить VPN на время входа, потом включить снова.
- `git push` просит пароль: нужен Personal Access Token (Settings, Developer
  settings, Tokens, права `Contents: read/write`). Обычный пароль GitHub для
  push не годится.

## Совсем никак

Скажите, соберу `SmartPCAPParser-publish.zip`: bundle, exe и инструкция.
Архив можно отнести на машину с доступом или отправить тому, у кого он есть,
и опубликовать оттуда.
