"""Gráficas del benchmark: plano frente a TLS 1.3 + mTLS (PNG en evidences/bench/)."""
import matplotlib

matplotlib.use("Agg")  # sin ventana: funciona también en servidores sin pantalla
import matplotlib.pyplot as plt

from src import config

PLAIN, TLS = "#8a8f98", "#1f6feb"


def make_plots(out: dict) -> None:
    plain, tls = out["plain"], out["tls"]
    panels = [
        ("Handshake sin carga p50 (ms)", plain["connect_unloaded_ms"]["p50"], tls["connect_unloaded_ms"]["p50"]),
        ("Conexión con 300 a la vez p50 (ms)", plain["connect_ms"]["p50"], tls["connect_ms"]["p50"]),
        ("RTT mensaje 256 B p50 (ms)", plain["rtt_small_ms"]["p50"], tls["rtt_small_ms"]["p50"]),
        ("Throughput (MB/s)", plain["throughput_MBps"], tls["throughput_MBps"]),
        ("CPU del servidor por MB (ms/MB)", plain["cpu_ms_per_MB"], tls["cpu_ms_per_MB"]),
        ("RAM servidor, pico (MB)", plain["transfer_phase"]["ram_peak_mb"], tls["transfer_phase"]["ram_peak_mb"]),
    ]
    fig, axes = plt.subplots(2, 3, figsize=(12, 6.4))
    for ax, (title, a, b) in zip(axes.flat, panels):
        bars = ax.bar(["Plano", "TLS 1.3\n+ mTLS"], [a, b], color=[PLAIN, TLS], width=0.6)
        ax.set_title(title, fontsize=11)
        for bar, v in zip(bars, (a, b)):
            ax.annotate(f"{v:.1f}", (bar.get_x() + bar.get_width() / 2, v), ha="center",
                        va="bottom", fontsize=10)
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle(f"Overhead de TLS 1.3 + mTLS con {out['sessions']} sesiones simultáneas "
                 f"(mediana de {out['runs']} ejecuciones)", fontsize=13)
    fig.tight_layout()
    config.BENCH_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(config.BENCH_DIR / "benchmark_comparison.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 3.8))
    labels = ["p50", "p95", "p99"]
    x = range(3)
    ax.bar([i - 0.2 for i in x], [plain["rtt_small_ms"][k] for k in labels], 0.4, label="Plano", color=PLAIN)
    ax.bar([i + 0.2 for i in x], [tls["rtt_small_ms"][k] for k in labels], 0.4, label="TLS 1.3 + mTLS", color=TLS)
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("ms")
    ax.set_title("Latencia (RTT) de un mensaje de 256 B con 300 sesiones activas")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(config.BENCH_DIR / "benchmark_latency.png", dpi=150)
    plt.close(fig)
