# Taokari per-pass ablation

Native baseline: size 141.0KB, runtime 414.00ms total.

## Biggest binary-size cost

| pass           |                         metrics                          |
|----------------|----------------------------------------------------------|
| indbr_l4       | size    153.0KB ( 1.08x) | run 10444.00ms (25.23x) | build   1.57s |
| indbr_l3       | size    151.5KB ( 1.07x) | run  5445.00ms (13.15x) | build   1.61s |
| icall_l4       | size    147.5KB ( 1.05x) | run  4949.00ms (11.95x) | build   1.42s |
| indbr_l2       | size    146.5KB ( 1.04x) | run  2226.00ms ( 5.38x) | build   1.44s |
| icall_l3       | size    146.5KB ( 1.04x) | run  4247.00ms (10.26x) | build   1.43s |
| indbr_l1       | size    145.5KB ( 1.03x) | run  1956.00ms ( 4.72x) | build   1.45s |
| fla_l3         | size    145.0KB ( 1.03x) | run  1569.00ms ( 3.79x) | build   1.42s |
| fla_l4         | size    145.0KB ( 1.03x) | run  1794.00ms ( 4.33x) | build   1.42s |

## Biggest runtime cost

| pass           |                         metrics                          |
|----------------|----------------------------------------------------------|
| indbr_l4       | size    153.0KB ( 1.08x) | run 10444.00ms (25.23x) | build   1.57s |
| indbr_l3       | size    151.5KB ( 1.07x) | run  5445.00ms (13.15x) | build   1.61s |
| icall_l4       | size    147.5KB ( 1.05x) | run  4949.00ms (11.95x) | build   1.42s |
| icall_l3       | size    146.5KB ( 1.04x) | run  4247.00ms (10.26x) | build   1.43s |
| icall_l2       | size    144.5KB ( 1.02x) | run  2784.00ms ( 6.72x) | build   1.42s |
| indbr_l2       | size    146.5KB ( 1.04x) | run  2226.00ms ( 5.38x) | build   1.44s |
| cie_l3         | size    142.5KB ( 1.01x) | run  1963.00ms ( 4.74x) | build   1.45s |
| cie_l4         | size    142.5KB ( 1.01x) | run  1962.00ms ( 4.74x) | build   1.47s |

## Biggest compile-time cost

| pass           |                         metrics                          |
|----------------|----------------------------------------------------------|
| indbr_l3       | size    151.5KB ( 1.07x) | run  5445.00ms (13.15x) | build   1.61s |
| indbr_l4       | size    153.0KB ( 1.08x) | run 10444.00ms (25.23x) | build   1.57s |
| mba_l2         | size    141.5KB ( 1.00x) | run   440.00ms ( 1.06x) | build   1.54s |
| bcf_l4         | size    143.0KB ( 1.01x) | run   431.00ms ( 1.04x) | build   1.52s |
| meta_on        | size    141.0KB ( 1.00x) | run   396.00ms ( 0.96x) | build   1.52s |
| mba_l1         | size    141.5KB ( 1.00x) | run   417.00ms ( 1.01x) | build   1.51s |
| fla_l1         | size    144.0KB ( 1.02x) | run  1084.00ms ( 2.62x) | build   1.49s |
| fla_l2         | size    144.0KB ( 1.02x) | run  1116.00ms ( 2.70x) | build   1.49s |
