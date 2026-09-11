# Shadowrocket + RoscomVPN

Маршрутизация [RoscomVPN](https://github.com/hydraponique/roscomvpn-routing) для Shadowrocket:
короткий конфиг плюс внешние списки правил, которые пересобираются из апстрима автоматически.

## Идея

RoscomVPN публикует правила в форматах `geosite.dat`/`geoip.dat` (Xray), `.mrs` (Mihomo) и
`.srs` (sing-box). Shadowrocket ни один из них не читает. Зато исходники доменных списков
(ветка `master` репозитория `roscomvpn-geosite`, папка `data/`) и IP-списки (`roscomvpn-geoip`,
ветка `release`, папка `text/`) — обычный текст. Скрипт `build.py` переводит их в Surge-style
`.list`, который Shadowrocket подключает через `RULE-SET`. В самом конфиге только ссылки и
настройки, поэтому он умещается в сотню строк независимо от размера списков.

```
roscomvpn-geosite (master, data/*)  ─┐
                                      ├─> build.py ─> rules/*.list ─┐
roscomvpn-geoip (release, text/*.txt) ┘        │                    ├─> Shadowrocket (RULE-SET по URL)
                                               └─> roscomvpn.conf ──┘
                                                   roscomvpn-whitelist.conf
GitHub Actions: каждый день в 03:40 UTC (после сборки geoip у RoscomVPN), при пуше и вручную
```

## Файлы

| Файл | Что это |
|---|---|
| `roscomvpn.conf` | профиль DEFAULT: RU/BY напрямую, YouTube/Telegram/GitHub/Google Play через прокси, реклама и телеметрия режутся |
| `roscomvpn-whitelist.conf` | профиль WHITELIST: напрямую только белые списки РФ, всё остальное через прокси |
| `rules/*.list` | сгенерированные списки (коммитятся, чтобы ссылки работали сразу) |
| `build.py` | конвертер и сборщик, только стандартная библиотека Python 3.9+ |
| `templates/*.conf.tmpl` | шаблоны конфигов с плейсхолдерами `{BASE_URL}` и `{BUILD_DATE}` |
| `.github/workflows/update.yml` | автообновление списков и конфигов |
| `tests/test_build.py` | тесты конвертера и сборки |
| `default.conf` | исходный шаблон Shadowrocket, оставлен для справки |

## Установка

1. Создайте на GitHub **публичный** репозиторий, например `shadowrocket-roscomvpn`
   (raw-ссылки должны открываться без авторизации).
2. Загрузите в него содержимое этой папки:

   ```bash
   git init && git add . && git commit -m "Shadowrocket + RoscomVPN" && git branch -M main && git remote add origin git@github.com:USER/shadowrocket-roscomvpn.git && git push -u origin main
   ```

3. Откройте вкладку Actions и дождитесь первого запуска workflow «Update rules from RoscomVPN».
   Он сам подставит адрес вашего репозитория в конфиги и списки. Если пуш из workflow
   отклоняется, проверьте Settings → Actions → General → Workflow permissions →
   «Read and write permissions».
4. В Shadowrocket: **Config → «+» (Add Config)** и вставьте ссылку:

   ```
   https://raw.githubusercontent.com/USER/shadowrocket-roscomvpn/main/roscomvpn.conf
   ```

   Затем нажмите на конфиг → **Use Config**. Списки скачаются при первом применении.
5. **Settings → Auto Update → Config**: включите автообновление (интервал 1 день).
   Вместе с конфигом Shadowrocket перекачивает и все `RULE-SET`.

Профиль WHITELIST подключается той же ссылкой с `roscomvpn-whitelist.conf` на конце.

До первого запуска workflow конфиги в этой папке собраны для адреса
`https://raw.githubusercontent.com/sandric911/shadowrocket-roscomvpn/main`. Если репозиторий
называется иначе, ничего править не нужно: workflow пересоберёт файлы под реальный адрес.

## Что куда идёт (профиль DEFAULT)

Порядок правил повторяет `MIHOMO/default.yaml` у RoscomVPN.

| Политика | Списки | Зачем |
|---|---|---|
| DIRECT | `geoip-private`, `private` | локальные сети и служебные домены |
| REJECT-NO-DROP | UDP/443 | блок QUIC, приложения откатываются на TCP |
| REJECT | `category-ads`, `win-spy` | реклама VK/Mail.ru, телеметрия Windows |
| DIRECT | `torrent` | трекеры и DHT мимо прокси, бережём сервер |
| PROXY | `google-play`, `twitch-ads`, `youtube`, `telegram`, `github` | то, что ломают ТСПУ и РКН |
| DIRECT | `epicgames`, `origin`, `riot`, `escapefromtarkov`, `steam`, `faceit` | игры: экономия трафика, ниже пинг |
| DIRECT | `twitch`, `microsoft`, `apple`, `pinterest` | сервисы, которым прокси не нужен |
| DIRECT | `category-ru`, `whitelist` | российские домены, банки ЦБ РФ, госуслуги |
| DIRECT | `geoip-direct` | «хирургический» geoip:direct: RU/BY минус списки РКН и зарубежные CDN |
| PROXY | FINAL | всё остальное |

Последний IP-список подключён без `no-resolve` намеренно: неизвестный домен резолвится через
`dns-server`, и если адрес российский — идёт напрямую. Так работает `IPIfNonMatch` у RoscomVPN.

DNS тоже как у RoscomVPN: Яндекс `77.88.8.8` (работает в РФ при белых списках и шатдаунах) и
Google `8.8.8.8` по DoH параллельно, побеждает самый быстрый ответ. Резерв: обычный DNS
Яндекса, Google через прокси, системный DNS.

## Чем отличается от оригинала

- IPv6 выключен через `ipv6 = false` вместо правила `IP-CIDR,::/0,REJECT-DROP`: списки
  RoscomVPN только IPv4, а выключенный IPv6 в Shadowrocket не заставляет приложения ждать таймаута.
- Для рекламы и телеметрии `REJECT` вместо `REJECT-DROP`: мгновенный отказ вместо зависания.
- Записи `regexp:` переводятся в `DOMAIN-KEYWORD` по буквальному началу регулярки
  (в Shadowrocket нет регулярок по домену). В используемых списках таких записей две:
  из `github` получается `DOMAIN-KEYWORD,github-production-release-asset-`, а регулярка
  одиночных хостов из `private` выбрасывается.
- Правила по имени процесса (`custom-category`: games, ru-apps, torrent-clients, Discord)
  не переносятся: на iOS их не существует.
- Списки `category-geoblock-ru` и `google-deepmind` не используются: они для серверной
  маршрутизации RU-сервер → зарубеж.
- Торренты: в DEFAULT — DIRECT (как в Mihomo-конфиге), в WHITELIST — REJECT (как в Happ-профиле).
  Поменять — одно слово в шаблоне.

## Локальная сборка и проверка

```bash
python3 build.py --base-url https://raw.githubusercontent.com/USER/REPO/main
```

```bash
python3 build.py --check
```

```bash
python3 -m unittest discover -s tests -v
```

`--src-dir ПАПКА` собирает из локальной копии источников (`geosite/<name>`, `geoip/<name>.txt`)
без сети. Списки перезаписываются только при изменении содержимого, метка `# GENERATED`
не считается изменением, поэтому workflow не плодит пустые коммиты.

## Варианты, если что-то не устраивает

- **Большой IP-список тормозит.** В `geoip-direct.list` около 36 000 CIDR. Замените строку
  `RULE-SET,…/geoip-direct.list,DIRECT` на закомментированные `GEOIP,RU,DIRECT` и
  `GEOIP,BY,DIRECT`: встроенная база легче, но без исключений РКН и зарубежных CDN.
- **raw.githubusercontent.com плохо открывается.** В workflow замените `BASE_URL` на
  `https://cdn.jsdelivr.net/gh/${{ github.repository }}@main` и запустите его вручную.
- **Хочется geoip как у RoscomVPN, но без списка.** Инструмент
  [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) умеет собирать `Country.mmdb`
  из тех же текстовых списков; база задаётся в Shadowrocket → Settings → GeoLite2 Database и
  подменяет встроенную. Здесь не сделано: нужен ручной шаг в приложении, и пропадает
  `GEOIP` по странам.
- **Свой прокси-выбор по сервисам.** Политику в строке `RULE-SET` можно заменить на имя
  группы или сервера из Shadowrocket, например `RULE-SET,…/youtube.list,YouTube-Group`.
