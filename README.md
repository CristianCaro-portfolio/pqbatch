# pqbatch

Firmas poscuánticas para streams de eventos sin pagar 50 veces más bytes.

## El problema

Los equipos que firman cada evento, registro de auditoría o mensaje con Ed25519 o ECDSA tienen que pasar a firmas resistentes a computadores cuánticos. NIST deja de permitir las firmas clásicas después de 2035 y Google y Cloudflare se pusieron 2029 como meta interna. El reemplazo estándar es ML-DSA (FIPS 204). Una firma Ed25519 pesa 64 bytes y una ML-DSA-65 pesa 3309. Si se cambia una por otra, evento por evento, el stream crece varias veces y firmar se vuelve mucho más lento.

Las soluciones que existen para ese sobrecosto (Merkle Tree Certificates, MTL mode, batch signatures) están pensadas para certificados TLS y DNSSEC, no para un pipeline con muchos streams y un límite de latencia.

## Qué hace

Tres formas de firmar el mismo stream, con el mismo formato de bytes para poder compararlas:

- Una firma por evento. Ed25519 es lo que se usa hoy, ML-DSA es el cambio directo.
- v1, lote fijo con pruebas: una firma ML-DSA por cada N eventos y cada evento viaja con su prueba de inclusión Merkle. Es la receta de libro.
- v2, `Sealer`: los lotes cierran por tamaño o por tiempo límite, las pruebas no viajan (el lector recalcula el árbol y cualquiera puede generar una prueba después), los lotes de cada stream van encadenados por hash, y hay dos modos:
  - directo: cada lote lleva su firma ML-DSA.
  - anclado: cada lote lleva un sello Ed25519 inmediato y cada pocos segundos un solo checkpoint ML-DSA cubre a todos los streams con actividad.

Incluye además una herramienta de línea de comandos que sella un archivo JSON Lines con un archivo lateral, y una calculadora que estima el costo de cada esquema para una carga dada.

## Cómo correrlo

Python 3.10 o superior.

```
pip install -r requirements.txt
python -m pytest -q
python bench/download.py
python bench/run_bench.py
python bench/report.py
```

`download.py` baja una hora de eventos públicos de GitHub desde GH Archive (19 MB). `run_bench.py` tarda unos 15 minutos porque firma de verdad cada evento con ML-DSA en las líneas base. Con `--limit 20000` tarda unos 3 minutos. Los resultados quedan en `results/`.

Para usar la herramienta sobre un archivo:

```
python -m pqbatch.cli keygen --dir keys
python -m pqbatch.cli seal data/gh-2026-10-01-15.json.gz --keys keys --stream-field type
python -m pqbatch.cli verify data/gh-2026-10-01-15.json.gz --keys keys
```

Para dimensionar un caso propio:

```
python -m pqbatch.advisor --rate 2000 --streams 50 --event-bytes 400 --latency-ms 100 --finality-s 10
```

`examples/quickstart.py` muestra el uso desde código en 50 líneas.

Como referencia, sellar la hora completa de GitHub como archivo (85.569 líneas, 16 streams) agrega 13.315 bytes en total y una sola firma ML-DSA.

## Resultados

Datos: 85.569 eventos reales de GitHub del 1 de octubre de 2026, 15:00 UTC. 23,8 eventos por segundo, 1043 bytes en promedio, 16 tipos de evento, 43.149 dueños de repositorio (31.672 con un solo evento en la hora). Un núcleo de CPU, cryptography 50 con OpenSSL 4.0.2. La tabla completa está en `results/results.md`.

Una firma por evento:

| esquema | bytes por evento | eventos firmados por segundo |
|---|---:|---:|
| Ed25519 (hoy) | 64 | 21.500 |
| ML-DSA-65 (cambio directo) | 3309 | 840 |

Un solo stream con todo el tráfico, velocidad real:

| esquema | bytes por evento | espera p99 | firmas ML-DSA en la hora |
|---|---:|---:|---:|
| v1, lotes de 256 con pruebas | 275 | 20 s | 335 |
| v2 directo, límite 100 ms | 1111 | 100 ms | 28.618 |
| v2 anclado, 100 ms y checkpoint cada 10 s | 40 | 100 ms (10 s para la firma poscuántica) | 357 |

El mismo tráfico repetido 100 veces más rápido (2.377 eventos por segundo): v2 directo baja a 13,9 bytes por evento y v2 anclado a 0,5. El modo anclado firma entre 37.000 y 120.000 eventos por segundo en un núcleo.

Un stream por dueño de repositorio (43.149 streams, casi todos con muy poco tráfico):

| esquema | bytes por evento |
|---|---:|
| ML-DSA-65 por evento | 3309 |
| v1 | 1766, con espera mediana de 33 minutos |
| v2 directo | 3318 |
| v2 anclado | 370 |
| v2 anclado, si cada lector sigue un solo stream y descarga sus checkpoints | 3594 |

La calculadora predijo los bytes por evento de v2 con un error de 0 a 11 por ciento en las doce configuraciones medidas.

## Dónde pierde

- Con muchos streams casi vacíos el modo anclado ahorra 9 veces frente al cambio directo, pero sigue costando casi 6 veces lo de Ed25519, porque cada stream necesita su camino Merkle hasta el checkpoint.
- Un lector aislado que verifica un solo evento necesita al menos una firma ML-DSA completa. Ahí no hay ahorro: el ahorro está en lo que se guarda y se transporta, no en lo que descarga un auditor solitario.
- v2 directo con poco tráfico y un límite corto casi no agrupa: 1111 bytes por evento a 24 eventos por segundo.
- En modo anclado un evento queda protegido solo por Ed25519 hasta que llega el checkpoint. Hoy eso equivale a la seguridad actual. Cuando exista un computador cuántico capaz, esa ventana es exposición real.
- La verificación es por lote: si se pierde un evento del lote, el lote entero queda sin verificar hasta recuperarlo.

## Límites

- Prototipo sin auditoría de seguridad. No usar en producción sin revisión de un criptógrafo.
- Los árboles usan SHA-256. Para niveles de seguridad 3 y 5 de NIST conviene SHA-384 o SHA-512, que alargan los caminos (`hash_name` es configurable).
- Los timestamps de GH Archive tienen resolución de un segundo. Los eventos de un mismo segundo se reparten de forma uniforme dentro de él.
- La repetición x100 comprime el tiempo del mismo tráfico. No es tráfico real de esa escala.
- No hay rotación de llaves, ni integración con Kafka, ni firma con HSM o KMS.
- ML-DSA en esta máquina firma unas 840 veces por segundo. Implementaciones optimizadas publican cifras varias veces mayores, así que la ventaja de CPU depende del hardware. La de bytes no.

## Qué es propio y qué no

Firmar una raíz Merkle en vez de cada mensaje es una idea vieja: Guardtime KSI (2013) y el firmado de logs por bloques de rsyslog, batch signatures (Aguilar-Melchor y otros, 2023), MTL mode de Verisign y Merkle Tree Certificates. Lo que este proyecto aporta es la versión para streams: lotes con tiempo límite, pruebas que no viajan, sello clásico inmediato con checkpoint poscuántico compartido entre streams, la medición sobre tráfico real contra el cambio directo, y la calculadora de dimensionamiento.

## Estructura

```
pqbatch/merkle.py     árbol Merkle con el formato de RFC 9162
pqbatch/keys.py       Ed25519 y ML-DSA con una interfaz común
pqbatch/records.py    formato binario de los registros
pqbatch/signers.py    PerEventSigner, FixedBatchSigner (v1) y Sealer (v2)
pqbatch/verifiers.py  lectores que detectan cualquier alteración
pqbatch/advisor.py    calculadora de costo por esquema
pqbatch/cli.py        sellar y verificar archivos JSON Lines
bench/                descarga de datos, benchmark y reporte
tests/                70 pruebas: árbol, pruebas de inclusión y ataques
```
