# Results

Data: https://data.gharchive.org/2026-10-01-15.json.gz
85569 events in 3600 s (23.8 per second), mean 1043 bytes, median 627 bytes, 16 event types, 43149 tenants (31672 with a single event).

Overhead is every byte added to the stream by signing. Throughput is events per second on one core.

## One signature per event

| scheme | bytes/event | % of payload | sign ev/s | verify ev/s |
|---|---:|---:|---:|---:|
| ed25519/event (today) | 64 | 6.1 | 21509 | 7645 |
| mldsa44/event | 2420 | 231.9 | 1361 | 6877 |
| mldsa65/event (direct swap) | 3309 | 317.1 | 842 | 4410 |

## Batched schemes

x1 is the real traffic, x100 the same events replayed 100 times faster. `lone reader` is the cost when every reader follows one stream and downloads each checkpoint it needs.

| streams | replay | scheme | bytes/event | % of payload | lone reader bytes/event | PQ signatures | sign ev/s | verify ev/s | wait p50 ms | wait p99 ms | PQ wait p99 ms |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firehose | x1 | v1 fixed 256 + proofs | 275.1 | 26.37 | 275.1 | 335 | 76683 | 55604 | 4988 | 20386 | 20386 |
| firehose | x1 | v2 direct 100ms | 1111.4 | 106.51 | 1111.4 | 28618 | 2463 | 12162 | 62 | 100 | 100 |
| firehose | x1 | v2 anchored 100ms/10s | 40.2 | 3.86 | 54.3 | 357 | 37084 | 19438 | 62 | 100 | 10025 |
| firehose | x1 | v2 anchored 100ms/10s, pq only | 18.8 | 1.80 | 32.9 | 357 | 64311 | 131399 | 62 | 100 | 10025 |
| firehose | x100 | v1 fixed 256 + proofs | 275.1 | 26.37 | 275.1 | 335 | 72951 | 56862 | 50 | 204 | 204 |
| firehose | x100 | v2 direct 100ms | 13.9 | 1.34 | 13.9 | 359 | 85526 | 148523 | 51 | 99 | 99 |
| firehose | x100 | v2 anchored 100ms/10s | 0.5 | 0.05 | 0.6 | 4 | 122456 | 157940 | 51 | 99 | 10009 |
| firehose | x100 | v2 anchored 100ms/10s, pq only | 0.2 | 0.02 | 0.4 | 4 | 155589 | 174106 | 51 | 99 | 10009 |
| type | x1 | v1 fixed 256 + proofs | 275.1 | 26.36 | 275.1 | 344 | 65977 | 57097 | 8361 | 933941 | 933941 |
| type | x1 | v2 direct 100ms | 1585.2 | 151.92 | 1585.2 | 40819 | 1759 | 8803 | 77 | 100 | 100 |
| type | x1 | v2 anchored 100ms/10s | 56.3 | 5.39 | 180.8 | 358 | 28509 | 14293 | 77 | 100 | 10023 |
| type | x1 | v2 anchored 100ms/10s, pq only | 25.8 | 2.47 | 150.3 | 358 | 64283 | 121428 | 77 | 100 | 10023 |
| type | x100 | v1 fixed 256 + proofs | 275.1 | 26.36 | 275.1 | 344 | 59902 | 56692 | 84 | 9339 | 9339 |
| type | x100 | v2 direct 100ms | 106.9 | 10.25 | 106.9 | 2754 | 21974 | 75204 | 52 | 100 | 100 |
| type | x100 | v2 anchored 100ms/10s | 2.8 | 0.27 | 5.2 | 4 | 123102 | 99008 | 52 | 100 | 9982 |
| type | x100 | v2 anchored 100ms/10s, pq only | 0.7 | 0.07 | 3.2 | 4 | 149465 | 173083 | 52 | 100 | 9982 |
| tenant | x1 | v1 fixed 256 + proofs | 1765.8 | 169.23 | 1765.8 | 43150 | 1663 | 7863 | 2012905 | 3575084 | 3575084 |
| tenant | x1 | v2 direct 100ms | 3317.9 | 317.99 | 3317.9 | 85438 | 830 | 4246 | 100 | 100 | 100 |
| tenant | x1 | v2 anchored 100ms/10s | 370.5 | 35.51 | 3594.5 | 359 | 13816 | 6261 | 100 | 100 | 10023 |
| tenant | x1 | v2 anchored 100ms/10s, pq only | 306.6 | 29.38 | 3530.6 | 359 | 36256 | 37047 | 100 | 100 | 10023 |
| tenant | x100 | v1 fixed 256 + proofs | 1765.8 | 169.23 | 1765.8 | 43150 | 1632 | 8116 | 20129 | 35751 | 35751 |
| tenant | x100 | v2 direct 100ms | 3098.4 | 296.96 | 3098.4 | 79786 | 892 | 4364 | 100 | 100 | 100 |
| tenant | x100 | v2 anchored 100ms/10s | 369.9 | 35.46 | 2457.3 | 4 | 16456 | 6477 | 100 | 100 | 10009 |
| tenant | x100 | v2 anchored 100ms/10s, pq only | 310.3 | 29.74 | 2397.6 | 4 | 41616 | 37185 | 100 | 100 | 10009 |

## Anchored mode on tenant streams, real speed

| batch deadline ms | checkpoint s | bytes/event | PQ signatures |
|---:|---:|---:|---:|
| 10 | 1 | 398.8 | 3451 |
| 10 | 10 | 370.6 | 359 |
| 10 | 60 | 393.8 | 60 |
| 100 | 1 | 398.6 | 3450 |
| 100 | 10 | 370.5 | 359 |
| 100 | 60 | 393.7 | 60 |
| 1000 | 1 | 396.9 | 3447 |
| 1000 | 10 | 369.6 | 359 |
| 1000 | 60 | 393.0 | 60 |

## Sizing model against the replay

| streams | replay | scheme | predicted bytes/event | measured | error |
|---|---|---|---:|---:|---:|
| firehose | x1 | v2 direct 100ms | 984.0 | 1111.4 | -11% |
| firehose | x1 | v2 anchored 100ms/10s | 37.2 | 40.2 | -8% |
| firehose | x100 | v2 direct 100ms | 13.9 | 13.9 | -0% |
| firehose | x100 | v2 anchored 100ms/10s | 0.5 | 0.5 | -4% |
| type | x1 | v2 direct 100ms | 1598.2 | 1585.2 | +1% |
| type | x1 | v2 anchored 100ms/10s | 57.3 | 56.3 | +2% |
| type | x100 | v2 direct 100ms | 109.0 | 106.9 | +2% |
| type | x100 | v2 anchored 100ms/10s | 2.8 | 2.8 | +1% |
| tenant | x1 | v2 direct 100ms | 3321.4 | 3317.9 | +0% |
| tenant | x1 | v2 anchored 100ms/10s | 367.9 | 370.5 | -1% |
| tenant | x100 | v2 direct 100ms | 3195.5 | 3098.4 | +3% |
| tenant | x100 | v2 anchored 100ms/10s | 355.1 | 369.9 | -4% |

## Auditing one event on its own

Batch of 272 events, proof of 9 hashes built on demand: 3787 bytes in total (proof, previous chain head, seal, anchor and checkpoint).
