#!/usr/bin/env python3
"""
Experimental testbed for the post-quantum migration of a hybrid-blockchain
medical ledger.

E1  Primitive benchmarks on native implementations
    - ECDSA P-256: OpenSSL 3 via the `cryptography` package
    - ML-DSA-44/65/87, Falcon-512/1024, SPHINCS+-SHA2-128s: liboqs (C)
E2  Ledger testbed: real transactions (800-byte payload, k endorser signatures
    over its SHA-256 digest), packed into 2 MB blocks, then validated.
    Reports measured transaction and block sizes and the time to validate the
    SAME transaction volume under every scheme (reviewer A, comment 3).
E3  Throughput with network propagation, PBFT-style consensus rounds and the
    real national load (reviewer A, comment 2).

All timings: medians over repeated runs, single thread.
"""
import ctypes
import ctypes.util
import hashlib
import json
import os
import platform
import statistics as st
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

OQS = ctypes.CDLL(os.environ.get("OQS_LIB", "oqs/lib/liboqs.so"))
OQS.OQS_init()


class OQS_SIG(ctypes.Structure):
    _fields_ = [("method_name", ctypes.c_char_p), ("alg_version", ctypes.c_char_p),
                ("claimed_nist_level", ctypes.c_uint8), ("euf_cma", ctypes.c_bool),
                ("sig_with_ctx_support", ctypes.c_bool),
                ("length_public_key", ctypes.c_size_t),
                ("length_secret_key", ctypes.c_size_t),
                ("length_signature", ctypes.c_size_t)]


OQS.OQS_SIG_new.restype = ctypes.POINTER(OQS_SIG)
OQS.OQS_SIG_new.argtypes = [ctypes.c_char_p]
OQS.OQS_SIG_keypair.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.c_char_p, ctypes.c_char_p]
OQS.OQS_SIG_sign.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.c_char_p,
                             ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p,
                             ctypes.c_size_t, ctypes.c_char_p]
OQS.OQS_SIG_verify.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.c_char_p, ctypes.c_size_t,
                               ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]


class PQ:
    def __init__(self, name):
        self.s = OQS.OQS_SIG_new(name.encode())
        if not self.s:
            raise RuntimeError(name)
        m = self.s.contents
        self.level = m.claimed_nist_level
        self.lpk, self.lsk, self.lsig = m.length_public_key, m.length_secret_key, m.length_signature

    def keypair(self):
        pk = ctypes.create_string_buffer(self.lpk); sk = ctypes.create_string_buffer(self.lsk)
        assert OQS.OQS_SIG_keypair(self.s, pk, sk) == 0
        return pk.raw, sk.raw

    def sign(self, sk, msg):
        sig = ctypes.create_string_buffer(self.lsig); n = ctypes.c_size_t(0)
        assert OQS.OQS_SIG_sign(self.s, sig, ctypes.byref(n), msg, len(msg), sk) == 0
        return sig.raw[:n.value]

    def verify(self, pk, msg, sig):
        return OQS.OQS_SIG_verify(self.s, msg, len(msg), sig, len(sig), pk) == 0


class ECDSA:
    level = 1          # classical 128-bit; no quantum security

    def keypair(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.CompressedPoint)
        return pk, sk

    def sign(self, sk, msg):
        return sk.sign(msg, ec.ECDSA(hashes.SHA256()))

    def load(self, pk):
        """Decode once, as a validator caches endorser identities."""
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)

    def verify(self, pk, msg, sig):
        key = pk if not isinstance(pk, bytes) else self.load(pk)
        try:
            key.verify(sig, msg, ec.ECDSA(hashes.SHA256())); return True
        except Exception:
            return False


SCHEMES = {
    "ECDSA P-256": (ECDSA, None, 0),
    "Falcon-512": (PQ, "Falcon-512", 1),
    "Falcon-1024": (PQ, "Falcon-1024", 5),
    "ML-DSA-44": (PQ, "ML-DSA-44", 2),
    "ML-DSA-65": (PQ, "ML-DSA-65", 3),
    "ML-DSA-87": (PQ, "ML-DSA-87", 5),
    "SLH-DSA-128s": (PQ, "SPHINCS+-SHA2-128s-simple", 1),
}

K = 5                       # endorsement signatures per transaction
B0 = 800                    # payload bytes
B_MAX = 2_000_000           # block size limit
R_YEAR = 1e8                # transactions per year (national scale)
VOLUME = 1000               # same-volume comparison: 1,000 transactions


def med_ms(f, n):
    out = []
    for _ in range(n):
        t = time.perf_counter_ns(); f(); out.append(time.perf_counter_ns() - t)
    return st.median(out) / 1e6


def bench(name):
    cls, arg, _ = SCHEMES[name]
    s = cls(arg) if arg else cls()
    msg = hashlib.sha256(b"consent-transaction").digest()
    pk, sk = s.keypair()
    nsig = 20 if "SLH" in name else 300
    sigs = [s.sign(sk, msg) for _ in range(nsig)]
    sig_len = st.mean(len(x) for x in sigs)
    t_sign = med_ms(lambda: s.sign(sk, msg), nsig)
    vk = s.load(pk) if hasattr(s, "load") else pk
    t_ver = med_ms(lambda: s.verify(vk, msg, sigs[0]), 2000)
    t_ver_uncached = med_ms(lambda: s.verify(pk, msg, sigs[0]), 2000)
    assert s.verify(pk, msg, sigs[0]) and not s.verify(pk, msg[:-1] + b"\x00", sigs[0])
    return s, {"pk_bytes": len(pk), "sig_bytes_mean": round(sig_len, 1),
               "sig_bytes_max": max(len(x) for x in sigs),
               "sign_ms": t_sign, "verify_ms": t_ver, "verify_ms_uncached_key": t_ver_uncached,
               "nist_level": SCHEMES[name][2]}


def ledger(name, s):
    """Build real transactions and blocks; validate a fixed transaction volume."""
    endorsers = [s.keypair() for _ in range(K)]
    cache = {pk: (s.load(pk) if hasattr(s, "load") else pk) for pk, _ in endorsers}
    rnd = os.urandom

    def make_tx():
        payload = rnd(B0)
        digest = hashlib.sha256(payload).digest()
        parts = [struct.pack(">I", len(payload)), payload, struct.pack(">B", K)]
        ends = []
        for pk, sk in endorsers:
            sig = s.sign(sk, digest)
            parts += [struct.pack(">HH", len(pk), len(sig)), pk, sig]
            ends.append((pk, sig))
        return b"".join(parts), digest, ends

    n_pool = 40 if "SLH" in name else 400          # SLH-DSA signing is very slow
    pool = [make_tx() for _ in range(n_pool)]
    tx_sizes = [len(t[0]) for t in pool]
    tx_mean = st.mean(tx_sizes)
    per_block = int(B_MAX // tx_mean)

    def validate(txs):
        for raw, digest, ends in txs:
            assert hashlib.sha256(raw[4:4 + B0]).digest() == digest
            for pk, sig in ends:
                if not s.verify(cache[pk], digest, sig):
                    raise ValueError("bad signature")

    vol = [pool[i % n_pool] for i in range(VOLUME)]
    t_vol = med_ms(lambda: validate(vol), 7)                  # same volume, all schemes
    blk = [pool[i % n_pool] for i in range(per_block)]
    t_blk = med_ms(lambda: validate(blk), 5)                  # one full block
    return {"tx_bytes_mean": round(tx_mean, 1), "tx_per_block": per_block,
            "block_bytes": round(per_block * tx_mean),
            "validate_1000tx_ms": t_vol, "validate_block_ms": t_blk,
            "per_tx_ms": t_vol / VOLUME,
            "growth_TB_year": R_YEAR * tx_mean / 1e12}


def throughput(row, bw_mbit, rtt_ms, tau_s=1.0, phases=3):
    """Committed tx/s for one block per round: PBFT pre-prepare carries the block,
    prepare/commit add (phases-1) round trips; validation runs once per block."""
    t_net = row["block_bytes"] * 8 / (bw_mbit * 1e6) + phases * rtt_ms / 1e3
    t_round = max(tau_s, t_net + row["validate_block_ms"] / 1e3)
    return row["tx_per_block"] / t_round, t_net


def main():
    flags = open("/proc/cpuinfo").read()
    env = {"cpu": [l.split(":")[1].strip() for l in flags.splitlines() if l.startswith("model name")][0],
           "avx2": " avx2 " in flags,
           "python": platform.python_version(),
           "liboqs": "0.12.0", "openssl": __import__("ssl").OPENSSL_VERSION,
           "k_endorsements": K, "payload_bytes": B0, "block_limit_bytes": B_MAX,
           "annual_tx": R_YEAR}
    rows = {}
    for name in SCHEMES:
        s, b = bench(name)
        b.update(ledger(name, s))
        rows[name] = b
        print(f"{name:13s} sig {b['sig_bytes_mean']:7.1f}B pk {b['pk_bytes']:5d}B "
              f"sign {b['sign_ms']:8.3f}ms verify {b['verify_ms']:6.3f}ms | "
              f"tx {b['tx_bytes_mean']:7.0f}B blk {b['tx_per_block']:5d} | "
              f"1000tx {b['validate_1000tx_ms']:8.1f}ms block {b['validate_block_ms']:7.1f}ms")

    base = rows["ECDSA P-256"]
    for r in rows.values():
        r["inflation"] = r["tx_bytes_mean"] / base["tx_bytes_mean"]
        r["cpu_vs_ecdsa"] = r["validate_1000tx_ms"] / base["validate_1000tx_ms"]
        r["cpu_hours_year"] = R_YEAR * r["per_tx_ms"] / 3.6e6

    scen = {"LAN (1 Gbit/s, RTT 1 ms)": (1000, 1), "inter-city (100 Mbit/s, RTT 20 ms)":
            (100, 20), "regional (10 Mbit/s, RTT 50 ms)": (10, 50)}
    peak = R_YEAR / 31_536_000 * 10                       # 10x the mean arrival rate
    for name, r in rows.items():
        r["throughput"] = {}
        for sc, (bw, rtt) in scen.items():
            tps, tnet = throughput(r, bw, rtt)
            r["throughput"][sc] = {"tps": tps, "net_s": tnet,
                                   "headroom_vs_peak": tps / peak}
    out = {"env": env, "peak_tps": peak, "scenarios": list(scen), "rows": rows}
    json.dump(out, open("results/results.json", "w"), indent=1)
    print(f"\npeak load: {peak:.1f} tx/s")
    for name, r in rows.items():
        print(f"{name:13s} " + " | ".join(
            f"{v['tps']:7.0f} tx/s ({v['headroom_vs_peak']:5.1f}x)" for v in r["throughput"].values())
              + f" | CPU {r['cpu_hours_year']:6.1f} h/yr, x{r['cpu_vs_ecdsa']:.2f} vs ECDSA")


if __name__ == "__main__":
    main()
