# sing-box-forkop

Ядро [Forkop](https://github.com/ushan0v/forkop): [sing-box](https://github.com/SagerNet/sing-box)
с доработками для роутеров на OpenWrt.

## Сборка

Понадобятся Linux или WSL, Go 1.21 или новее и git, а для пакетов apk ещё apk-tools.
Нужную версию Go `build.sh` скачает сам.

```sh
./build.sh --arch aarch64_cortex-a53   # пакеты ipk и apk для архитектуры роутера
./build.sh arm64 mipsle                # пакеты для выбранных целей
./build.sh --variant full arm64        # вариант full
./build.sh --list                      # варианты и цели
```

Готовые пакеты появятся в `dist/`. Вариант full при первой сборке скачивает исходники
cronet и тулчейн Chromium, это несколько гигабайт.
