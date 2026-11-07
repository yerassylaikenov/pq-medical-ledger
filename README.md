# Post-quantum signatures in a hybrid-blockchain medical ledger

Code, measurements and figures for the article

> Е. Ә. Айкенов. *Гибридті блокчейн медициналық жүйелерін кванттықтан кейінгі цифрлық
> қолтаңбаларға көшіру: тізілім көлемі мен өткізу қабілетін бағалау.*
> EKTU Journal of Information Security and Cryptography.

## What is measured

| Experiment | What it produces | Paper |
|---|---|---|
| E1 primitive benchmarks | signature/key sizes, sign and verify time for ECDSA P-256, Falcon-512/1024, ML-DSA-44/65/87, SLH-DSA-128s | Table 2, Fig. 1 |
| E2 ledger testbed | real transactions (800 B payload, k = 5 endorsements), 2 MB blocks, time to validate one block and the **same** 1,000 transactions | Table 3, Fig. 2, Fig. 4 |
| E3 network and consensus | effective throughput with propagation delay and three-phase (PBFT-style) consensus, three link scenarios, peak load 31.7 tx/s | Table 4, Fig. 3 |

Implementations: OpenSSL 3 (ECDSA, via `cryptography`) and liboqs 0.12.0 (post-quantum,
native C). SLH-DSA-128s is liboqs `SPHINCS+-SHA2-128s-simple`, whose sizes equal FIPS 205
SLH-DSA-SHA2-128s. Validators cache decoded endorser keys, as Fabric caches MSP identities.

## Reproduce

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./build_liboqs.sh                 # builds liboqs 0.12.0 into ./oqs (about 2 minutes)
python testbed.py                 # writes results/results.json (a few minutes)
python figures.py                 # writes figures/pq_g1.png ... pq_g4.png
```

`results/results.json` holds the measurements reported in the paper (Intel Xeon 2.3 GHz,
AVX2, one thread). Re-running on other hardware changes absolute times; sizes are
identical everywhere.

## Licence

MIT.
