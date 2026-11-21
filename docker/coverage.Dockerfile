# Образ замера для rrl-krb5: живой MIT KDC рядом с тем же компилятором.
#
# Зачем свой образ. Тесты tests/kdc.rs обёрнуты макросом `live!()`: без KRB5_TEST_KDC они выходят
# на первой строке, и замер показывает «90 passed за 0.00 с». Из-за этого client/u2u.rs,
# client/async_client.rs и часть client/fast.rs стоят на нуле не потому, что тестов нет, а
# потому, что живой KDC не поднимался: в образе rust:1.99.1-bullseye нет ни krb5kdc, ни
# kdb5_util, ни kadmin.local.
#
# Почему bookworm, а не bullseye, как в воротах. Компилятор тот же — 1.99.1, из того же
# официального образа; меняется только libc окружения (2.36 вместо 2.31), и на число покрытия
# это не влияет: инструментируется тот же код тем же rustc. А вот стенд без OpenSSL 3 не
# поднимается вовсе — `scripts/test-kdc.sh` строит просроченный CRL флагами
# `-crl_lastupdate`/`-crl_nextupdate`, которых в OpenSSL 1.1.1 из bullseye нет, и ошибка
# глотается внутри `o()`, поэтому отказ выглядит как «KDC не поднялся» без причины.
# Собирать бинарники для поставки здесь нельзя — для этого остаётся bullseye.
#
# pkinit и otp добавлены осознанно: стенд включает PKINIT и OTP только если нашёл плагины MIT,
# и без них часть тестов (вход по сертификату, анонимный PKINIT, RADIUS-OTP) тоже уходит в
# пропуск. python3 нужен скрипту RADIUS-сервера.
FROM rust:1.99.1-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Инструменты замера переносятся из нашего образа ворот: там они собраны и запинены, а версия их
# важна — cargo-mutants 27.1.0, cargo-llvm-cov 0.6.18, cargo-crap 0.9.0, cargo-dupes 0.2.1.
# Собранное на bullseye (glibc 2.31) работает на bookworm (2.36), обратное — нет.
COPY --from=rust:1.99.1-bullseye /usr/local/cargo/bin/cargo-llvm-cov /usr/local/cargo/bin/cargo-llvm-cov
COPY --from=rust:1.99.1-bullseye /usr/local/cargo/bin/cargo-crap /usr/local/cargo/bin/cargo-crap
COPY --from=rust:1.99.1-bullseye /usr/local/cargo/bin/cargo-dupes /usr/local/cargo/bin/cargo-dupes

# `cargo llvm-cov` вызывает llvm-cov и llvm-profdata из самого тулчейна; по умолчанию их там нет,
# а без них инструмент пишет «no such command», и это выглядит как незаданный CARGO_HOME.
RUN rustup component add llvm-tools-preview

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        krb5-kdc \
        krb5-admin-server \
        krb5-user \
        krb5-pkinit \
        krb5-otp \
        libkrb5-dev \
        openssl \
        python3 \
        procps \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Проверка внутри сборки, а не «образ собрался»: без этих команд стенд не поднимется, и тест
# молча уйдёт в пропуск — то есть отсутствие инструмента снова выглядело бы как нулевое
# покрытие кода. Версия OpenSSL проверяется отдельно: на 1.1.1 стенд падает без сообщения.
RUN set -eux; \
    for t in krb5kdc kdb5_util kadmin.local kadmind klist kinit; do \
        command -v "$t" >/dev/null || { echo "нет $t"; exit 1; }; \
    done; \
    ls /usr/lib/*/krb5/plugins/preauth/pkinit.so >/dev/null; \
    openssl version | grep -q '^OpenSSL 3' || { echo "нужен OpenSSL 3 для CRL стенда"; exit 1; }; \
    cargo llvm-cov --version; cargo crap --version; cargo dupes --version

LABEL org.opencontainers.image.description="rrl-krb5 coverage image: rust 1.99.1 with a live MIT KDC (not for shipping binaries)"
