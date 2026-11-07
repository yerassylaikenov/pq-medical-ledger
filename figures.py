#!/usr/bin/env python3
"""Figures 1-4 of the revised article, drawn from results.json (measured)."""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

R = json.load(open("results/results.json"))
rows = R["rows"]
NAMES = list(rows)
COL = {"ECDSA P-256": "#455A64", "Falcon-512": "#0F9D58", "Falcon-1024": "#7CB342",
       "ML-DSA-44": "#1B6CA8", "ML-DSA-65": "#5E35B1", "ML-DSA-87": "#8E24AA",
       "SLH-DSA-128s": "#C8102E"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.grid": True,
                     "grid.alpha": 0.3, "savefig.dpi": 300, "savefig.bbox": "tight",
                     "legend.frameon": False})


def fig1():
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    x = np.arange(len(NAMES)); w = 0.38
    sig = [rows[n]["sig_bytes_mean"] for n in NAMES]
    pk = [rows[n]["pk_bytes"] for n in NAMES]
    ax.bar(x - w / 2, sig, w, color=[COL[n] for n in NAMES], label="қолтаңба")
    ax.bar(x + w / 2, pk, w, color=[COL[n] for n in NAMES], alpha=0.45, label="ашық кілт")
    ax.set_yscale("log"); ax.set_xticks(x)
    ax.set_xticklabels(NAMES, rotation=22, ha="right", fontsize=9)
    ax.set_ylabel("өлшенген көлем, байт"); ax.legend(loc="upper left")
    fig.savefig("figures/pq_g1.png"); plt.close(fig)


def fig2():
    ks = [1, 3, 5, 7, 9]
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for n in NAMES:
        r = rows[n]
        tx = [800 + k * (r["sig_bytes_mean"] + r["pk_bytes"]) + 5 + 4 * k for k in ks]
        ax.plot(ks, tx, marker="o", ms=4, lw=1.8, color=COL[n], label=n)
        ax.scatter([5], [r["tx_bytes_mean"]], marker="x", s=60, color="black", zorder=5)
    ax.set_yscale("log"); ax.set_xticks(ks)
    ax.set_xlabel("қолдау қолтаңбаларының саны, k")
    ax.set_ylabel("транзакция көлемі, байт")
    ax.scatter([], [], marker="x", s=60, color="black", label="стендте өлшенген (k = 5)")
    ax.legend(fontsize=8, loc="upper left", bbox_to_anchor=(1.01, 1.0))
    fig.savefig("figures/pq_g2.png"); plt.close(fig)


def fig3():
    fig, (a, b) = plt.subplots(1, 2, figsize=(9.0, 3.5))
    g = [rows[n]["growth_TB_year"] for n in NAMES]
    a.bar(NAMES, g, color=[COL[n] for n in NAMES])
    a.set_ylabel("тізілім өсімі, ТБ/жыл")
    for i, v in enumerate(g):
        a.text(i, v + 0.06, f"{v:.2f}".replace(".", ","), ha="center", fontsize=8)
    a.set_ylim(0, max(g) * 1.15)
    a.set_xticks(range(len(NAMES))); a.set_xticklabels(NAMES, rotation=30, ha="right", fontsize=8)
    sc = R["scenarios"]; x = np.arange(len(NAMES)); w = 0.27
    labs = ["1 Гбит/с, RTT 1 мс", "100 Мбит/с, RTT 20 мс", "10 Мбит/с, RTT 50 мс"]
    shades = [1.0, 0.65, 0.35]
    for i, (s, lab, al) in enumerate(zip(sc, labs, shades)):
        b.bar(x + (i - 1) * w, [rows[n]["throughput"][s]["tps"] for n in NAMES], w,
              color=[COL[n] for n in NAMES], alpha=al, label=lab)
    b.axhline(R["peak_tps"], color="black", lw=1.2, ls=(0, (5, 3)))
    b.set_yscale("log"); b.set_ylabel("өткізу қабілеті, тр/с")
    b.set_xticks(x); b.set_xticklabels(NAMES, rotation=30, ha="right", fontsize=8)
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    b.legend(handles=[Patch(facecolor="#607D8B", alpha=al, label=lab)
                      for lab, al in zip(labs, shades)]
             + [Line2D([0], [0], color="black", lw=1.2, ls=(0, (5, 3)),
                       label=f"шыңдық жүктеме ({R['peak_tps']:.1f} тр/с)".replace(".", ","))],
             fontsize=7.5, loc="upper right")
    fig.tight_layout(w_pad=1.5); fig.savefig("figures/pq_g3.png"); plt.close(fig)


def fig4():
    base = rows["ECDSA P-256"]
    blk = [rows[n]["validate_block_ms"] / base["validate_block_ms"] for n in NAMES]
    vol = [rows[n]["validate_1000tx_ms"] / base["validate_1000tx_ms"] for n in NAMES]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    x = np.arange(len(NAMES)); w = 0.38
    ax.bar(x - w / 2, blk, w, color="#B0BEC5", label="бір блокқа (2 МБ)")
    ax.bar(x + w / 2, vol, w, color=[COL[n] for n in NAMES], label="бірдей көлемге (1000 тр.)")
    ax.axhline(1.0, color="black", lw=1.2, ls=(0, (5, 3)))
    for i, v in enumerate(vol):
        ax.text(i + w / 2, v + 0.06, f"{v:.2f}", ha="center", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(NAMES, rotation=22, ha="right", fontsize=9)
    ax.set_ylabel("тексеру уақыты, ECDSA = 1")
    ax.legend(loc="upper left")
    fig.savefig("figures/pq_g4.png"); plt.close(fig)


if __name__ == "__main__":
    fig1(); fig2(); fig3(); fig4(); print("figures written")
