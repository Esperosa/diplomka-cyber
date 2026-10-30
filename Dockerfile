# Produkcni gap audit (30.10.2026): pred timto souborem nesla appka rozjet
# jinak nez ze zdroju na stroji, co ji sestavil - "nikdo jiny to nerozjede"
# bylo doslovne pravda. Multi-stage build: UI bundle (Node/esbuild), Rust
# binarka (--release), a nakonec minimalni runtime image.
#
# NEOVERENO skutecnym `docker build`/`docker run` (Docker Desktop na vyvojovem
# stroji teto session nejde nastartovat - zapsano uz driv v produkcni-plan.md
# pri H5/broker praci). Napsano primo podle `src/paths.rs`'s runtime-base
# rozlisovani (exe adresar -> cwd -> compile-time fallback) a overenych
# zavislosti (rusqlite "bundled", reqwest "rustls-tls" - zadne libsqlite3/
# libssl na runtime nejsou potreba). Pred prvnim realnym nasazenim overit
# `docker build . && docker run --rm -p 8080:8080 <image> server spust ...`
# a vysledek zapsat do produkcni-plan.md jako samostatny, overeny krok.

FROM node:22-slim AS ui-builder
WORKDIR /src
COPY package.json package-lock.json tsconfig.ui.json tailwind.config.cjs ./
COPY scripts ./scripts
COPY ui-src ./ui-src
RUN npm ci
RUN npm run build:ui

FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin bakula-program

FROM debian:bookworm-slim AS runtime

# nmap: potreba pro --spustit-nmap (aktivni inventar sluzeb). ca-certificates:
# reqwest/rustls potrebuje duveryhodne koreny pro NVD/vulners/intel feedy.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nmap \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 bakula

WORKDIR /app
COPY --from=rust-builder /src/target/release/bakula-program /app/bakula-program
COPY --from=ui-builder /src/ui /app/ui
COPY resources /app/resources

# /data/workspace: ocekava se jako mountovany volume (docker-compose.yml) -
# drzi runs/, cache/, platform.sqlite, identity-registry.json atd. napric
# restarty kontejneru.
RUN mkdir -p /data/workspace && chown -R bakula:bakula /app /data

USER bakula
EXPOSE 8080

ENTRYPOINT ["/app/bakula-program"]
# --host 0.0.0.0 je nutne (vychozi je 127.0.0.1, nedosazitelne zvenku
# kontejneru). --workspace/--port lze prepsat pri `docker run`/compose.
CMD ["server", "spust", "--workspace", "/data/workspace", "--host", "0.0.0.0", "--port", "8080"]
