# NOTICE

Seznam externích zdrojů dat, softwaru a jejich licencí. Kód tohoto repozitáře je pod licencí uvedenou v [LICENSE](LICENSE); níže uvedené součásti mají vlastní licence, které tím nejsou dotčeny.

## Datasety

Podrobnosti (URL, kontrolní součty, výřezy, odchylky) jsou v [docs/diplomka/dataset-registry.md](docs/diplomka/dataset-registry.md). Licence jsou uvedeny tak, jak je zapsáno v registru.

| Dataset | Zdroj | Licence podle registru | Ve sledovaných souborech |
|---|---|---|---|
| IoT-23 | Stratosphere IPS / CTU (ČVUT), https://www.stratosphereips.org/datasets-iot23 | CC BY-NC-SA 4.0, pro výzkum | ano, malé výřezy `conn.log.labeled` v `labs/datasets/iot23/` |
| CTU-13 | Stratosphere IPS / CTU (ČVUT), https://www.stratosphereips.org/datasets-ctu13 | CC BY-NC-SA 4.0, pro výzkum | ne (`labs/datasets/ctu13/` je v `.gitignore`), v repozitáři jsou jen kód zdroje a kontrolní součty |
| CIC-IDS2017 (přegenerovaná verze Engelen a kol.) | https://www.unb.ca/cic/datasets/ids-2017.html, https://intrusion-detection.distrinet-research.be/WTMC2021/ | Bez výslovné licence, obě stránky žádají citaci (Sharafaldin, Lashkari, Ghorbani, ICISSP 2018; Engelen a kol., IEEE SPW/WTMC 2021) | ne, jen kód zdroje, skripty výřezu a kontrolní součty |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | „Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.“ Citovat pět článků z oficiální stránky | ne, jen kód zdroje, skripty výřezu a kontrolní součty |

Datasety zaznamenané v registru jako nepoužité (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES, DARPA OpTC, LANL Unified Host and Network) se nestahovaly a v repozitáři nejsou.

Upozornění k licencím dat:

- Soubory v `labs/datasets/iot23/` zůstávají pod licencí CC BY-NC-SA 4.0 (uvedení původu, nekomerční užití, stejné podmínky); licence kódu se na ně nevztahuje.
- Ostatní datasety (CTU-13, CIC-IDS2017, UNSW-NB15) se do repozitáře nedistribuují. Kdo je stahuje, řídí se podmínkami uvedenými výše.

## Písma

`ui-src/fonts/` obsahuje písma Sedmdvacet (Display, Mono, Text C) pod SIL Open Font License 1.1. Jde o odvozená díla písem Host Grotesk, JetBrains Mono a Public Sans; plné texty licencí jsou přiloženy u písem (`LICENSE.md`, `OFL.txt`, `OFL-HostGrotesk.txt`, `OFL-JetBrainsMono.txt`).

## Externí nástroje

Nmap, Suricata, Zeek, ProjectDiscovery `httpx` a `nuclei` se v repozitáři nedistribuují (viz `tools/projectdiscovery/README.md`); používají se jen jako volitelné externí programy podle jejich licencí. Lokální jazykový model pro asistenta (`models/skoky/`) obsahuje jen konfiguraci (`Modelfile`) nad základním modelem `qwen3:8b`; váhy modelu se nedistribuují a jejich licenci je třeba ověřit u poskytovatele modelu.

## Rust závislosti

Seznam vznikl z `cargo metadata --offline --filter-platform x86_64-pc-windows-msvc` a zahrnuje běžné a sestavovací závislosti dosažitelné z `bakula-program` (vývojové závislosti jsou vynechány). Verze odpovídají `Cargo.lock`. Metadata jiných platforem offline k dispozici nebyla; platformně specifické závislosti pro Linux a macOS proto v seznamu mohou chybět. Všechny uvedené licence jsou permisivní.

| Crate | Verze | Licence |
|---|---|---|
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| anyhow | 1.0.104 | MIT OR Apache-2.0 |
| arc-swap | 1.9.1 | MIT OR Apache-2.0 |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT |
| autocfg | 1.5.0 | Apache-2.0 OR MIT |
| axum | 0.8.8 | MIT |
| axum-core | 0.5.6 | MIT |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| bitflags | 2.11.0 | MIT OR Apache-2.0 |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| bytes | 1.11.1 | MIT |
| cc | 1.2.59 | MIT OR Apache-2.0 |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 |
| cfg_aliases | 0.2.1 | MIT |
| chacha20 | 0.10.2 | MIT OR Apache-2.0 |
| chrono | 0.4.44 | MIT OR Apache-2.0 |
| clap | 4.6.0 | MIT OR Apache-2.0 |
| clap_builder | 4.6.0 | MIT OR Apache-2.0 |
| clap_derive | 4.6.0 | MIT OR Apache-2.0 |
| clap_lex | 1.1.0 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| combine | 4.6.7 | MIT |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| displaydoc | 0.2.5 | MIT OR Apache-2.0 |
| either | 1.15.0 | MIT OR Apache-2.0 |
| equivalent | 1.0.2 | Apache-2.0 OR MIT |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 |
| fallible-streaming-iterator | 0.1.9 | MIT/Apache-2.0 |
| find-msvc-tools | 0.1.9 | MIT OR Apache-2.0 |
| foldhash | 0.1.5 | Zlib |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 |
| futures-channel | 0.3.32 | MIT OR Apache-2.0 |
| futures-core | 0.3.32 | MIT OR Apache-2.0 |
| futures-io | 0.3.32 | MIT OR Apache-2.0 |
| futures-macro | 0.3.32 | MIT OR Apache-2.0 |
| futures-sink | 0.3.32 | MIT OR Apache-2.0 |
| futures-task | 0.3.32 | MIT OR Apache-2.0 |
| futures-util | 0.3.32 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.2 | MIT OR Apache-2.0 |
| getrandom | 0.3.4 | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 |
| hashbrown | 0.15.5 | MIT OR Apache-2.0 |
| hashlink | 0.10.0 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| http | 1.4.0 | MIT OR Apache-2.0 |
| http-body | 1.0.1 | MIT |
| http-body-util | 0.1.3 | MIT |
| http-range-header | 0.4.2 | MIT |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| httpdate | 1.0.3 | MIT OR Apache-2.0 |
| hyper | 1.9.0 | MIT |
| hyper-rustls | 0.27.7 | Apache-2.0 OR ISC OR MIT |
| hyper-util | 0.1.20 | MIT |
| icu_collections | 2.2.0 | Unicode-3.0 |
| icu_locale_core | 2.2.0 | Unicode-3.0 |
| icu_normalizer | 2.2.0 | Unicode-3.0 |
| icu_normalizer_data | 2.2.0 | Unicode-3.0 |
| icu_properties | 2.2.0 | Unicode-3.0 |
| icu_properties_data | 2.2.0 | Unicode-3.0 |
| icu_provider | 2.2.0 | Unicode-3.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.1 | Apache-2.0 OR MIT |
| indexmap | 2.13.1 | Apache-2.0 OR MIT |
| ipnet | 2.12.0 | MIT OR Apache-2.0 |
| iri-string | 0.7.12 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itertools | 0.13.0 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 |
| libc | 0.2.184 | MIT OR Apache-2.0 |
| libsqlite3-sys | 0.31.0 | MIT |
| litemap | 0.8.2 | Unicode-3.0 |
| log | 0.4.29 | MIT OR Apache-2.0 |
| lru-slab | 0.1.2 | MIT OR Apache-2.0 OR Zlib |
| matchers | 0.2.0 | MIT |
| matchit | 0.8.4 | MIT AND BSD-3-Clause |
| memchr | 2.8.0 | Unlicense OR MIT |
| mime | 0.3.17 | MIT OR Apache-2.0 |
| mime_guess | 2.0.5 | MIT |
| mio | 1.2.0 | MIT |
| nu-ansi-term | 0.50.3 | MIT |
| num-bigint | 0.4.6 | MIT OR Apache-2.0 |
| num-integer | 0.1.46 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| pkg-config | 0.3.32 | MIT OR Apache-2.0 |
| potential_utf | 0.1.5 | Unicode-3.0 |
| ppv-lite86 | 0.2.21 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.106 | MIT OR Apache-2.0 |
| quinn | 0.11.9 | MIT OR Apache-2.0 |
| quinn-proto | 0.11.19 | MIT OR Apache-2.0 |
| quinn-udp | 0.5.14 | MIT OR Apache-2.0 |
| quote | 1.0.45 | MIT OR Apache-2.0 |
| rand | 0.10.3 | MIT OR Apache-2.0 |
| rand | 0.9.5 | MIT OR Apache-2.0 |
| rand_chacha | 0.9.0 | MIT OR Apache-2.0 |
| rand_core | 0.10.1 | MIT OR Apache-2.0 |
| rand_core | 0.9.5 | MIT OR Apache-2.0 |
| rand_pcg | 0.10.2 | MIT OR Apache-2.0 |
| redis | 0.27.6 | BSD-3-Clause |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| reqwest | 0.12.28 | MIT OR Apache-2.0 |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| roxmltree | 0.21.1 | MIT OR Apache-2.0 |
| rusqlite | 0.33.0 | MIT |
| rustc-hash | 2.1.2 | Apache-2.0 OR MIT |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.14.0 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.16 | ISC |
| rustversion | 1.0.22 | MIT OR Apache-2.0 |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| serde | 1.0.228 | MIT OR Apache-2.0 |
| serde_core | 1.0.228 | MIT OR Apache-2.0 |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 |
| serde_json | 1.0.145 | MIT OR Apache-2.0 |
| serde_path_to_error | 0.1.20 | MIT OR Apache-2.0 |
| serde_spanned | 1.1.1 | MIT OR Apache-2.0 |
| serde_urlencoded | 0.7.1 | MIT/Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha1_smol | 1.0.1 | BSD-3-Clause |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| sharded-slab | 0.1.7 | MIT |
| shlex | 1.3.0 | MIT OR Apache-2.0 |
| slab | 0.4.12 | MIT |
| smallvec | 1.15.1 | MIT OR Apache-2.0 |
| socket2 | 0.5.10 | MIT OR Apache-2.0 |
| socket2 | 0.6.3 | MIT OR Apache-2.0 |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.117 | MIT OR Apache-2.0 |
| sync_wrapper | 1.0.2 | Apache-2.0 |
| synstructure | 0.13.2 | MIT |
| thiserror | 2.0.18 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.18 | MIT OR Apache-2.0 |
| thread_local | 1.1.10 | MIT OR Apache-2.0 |
| tinystr | 0.8.3 | Unicode-3.0 |
| tinyvec | 1.11.0 | Zlib OR Apache-2.0 OR MIT |
| tinyvec_macros | 0.1.1 | MIT OR Apache-2.0 OR Zlib |
| tokio | 1.54.1 | MIT |
| tokio-macros | 2.7.0 | MIT |
| tokio-rustls | 0.26.4 | MIT OR Apache-2.0 |
| tokio-stream | 0.1.18 | MIT |
| tokio-util | 0.7.18 | MIT |
| toml | 0.9.12+spec-1.1.0 | MIT OR Apache-2.0 |
| toml_datetime | 0.7.5+spec-1.1.0 | MIT OR Apache-2.0 |
| toml_parser | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 |
| toml_writer | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 |
| tower | 0.5.3 | MIT |
| tower-http | 0.6.8 | MIT |
| tower-layer | 0.3.3 | MIT |
| tower-service | 0.3.3 | MIT |
| tracing | 0.1.44 | MIT |
| tracing-attributes | 0.1.31 | MIT |
| tracing-core | 0.1.36 | MIT |
| tracing-log | 0.2.0 | MIT |
| tracing-serde | 0.2.0 | MIT |
| tracing-subscriber | 0.3.23 | MIT |
| try-lock | 0.2.5 | MIT |
| typenum | 1.19.0 | MIT OR Apache-2.0 |
| unicase | 2.9.0 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| untrusted | 0.9.0 | ISC |
| url | 2.5.8 | MIT OR Apache-2.0 |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| uuid | 1.23.0 | Apache-2.0 OR MIT |
| vcpkg | 0.2.15 | MIT/Apache-2.0 |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| want | 0.3.1 | MIT |
| webpki-roots | 1.0.11 | CDLA-Permissive-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-sys | 0.60.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows-targets | 0.53.5 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.53.1 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| winnow | 0.7.15 | MIT |
| winnow | 1.0.1 | MIT |
| writeable | 0.6.3 | Unicode-3.0 |
| yoke | 0.8.2 | Unicode-3.0 |
| yoke-derive | 0.8.2 | Unicode-3.0 |
| zerocopy | 0.8.48 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerofrom | 0.1.7 | Unicode-3.0 |
| zerofrom-derive | 0.1.7 | Unicode-3.0 |
| zeroize | 1.8.2 | Apache-2.0 OR MIT |
| zerotrie | 0.2.4 | Unicode-3.0 |
| zerovec | 0.11.6 | Unicode-3.0 |
| zerovec-derive | 0.11.3 | Unicode-3.0 |
