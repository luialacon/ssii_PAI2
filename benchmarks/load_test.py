"""Benchmark de escalabilidad (RS3): 300 sesiones simultáneas, TLS 1.3 + mTLS frente a texto plano.

Qué hace, en cristiano:
  1. Arranca el servidor (cifrado o plano) en un PROCESO aparte, para poder medir su CPU y RAM.
  2. Lanza 300 "empleados" a la vez (cada uno con su propio certificado y usuario).
  3. Espera a que los 300 estén conectados y con login hecho (aquí se demuestra la simultaneidad).
  4. Los 300 mandan mensajes pequeños (latencia/RTT) y grandes (throughput).
  5. Todos hacen logout. Se repite varias veces y se guarda la mediana.

Los dos servidores comparten código y concurrencia (src/server/net.py y session.py): lo único que
cambia es el cifrado, así que la diferencia medida ES el sobrecoste de TLS 1.3 + mTLS.

    python -m benchmarks.load_test --runs 3
"""
import argparse
import asyncio
import json
import os
import socket
import statistics
import subprocess
import sys
import time

import psutil

from src import config
from src.client.byod_client import build_client_context
from src.pki.preload import preload_names
from src.protocol import arecv_frame, asend_frame

SMALL_BYTES, SMALL_COUNT = 256, 20          # mensajes para medir latencia
BIG_BYTES, BIG_COUNT = 32 * 1024, 10        # mensajes para medir throughput


def pct(values, p):
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]


def summarize(values_ms):
    return {"p50": pct(values_ms, 50), "p95": pct(values_ms, 95), "p99": pct(values_ms, 99),
            "mean": statistics.fmean(values_ms) if values_ms else 0.0}


# ------------------------------------------------------------------ servidor
def start_server(mode: str, port: int) -> subprocess.Popen:
    module = "src.server.gateway" if mode == "tls" else "src.server.plain_server"
    env = dict(os.environ, USECURE_AUDIT_LOG=str(config.BENCH_DIR / f"audit_{mode}.jsonl"))
    config.BENCH_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen([sys.executable, "-m", module, "--port", str(port)], env=env,
                            cwd=config.BASE_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection((config.HOST, port), timeout=0.5).close()
            return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"El servidor {mode} no arrancó")


class ResourceSampler:
    """Muestrea CPU (% de un núcleo) y RAM (RSS) del proceso servidor cada 0,2 s."""

    def __init__(self, pid):
        self.p = psutil.Process(pid)
        self.samples = []  # (t, cpu_%, rss_mb, cpu_segundos_acumulados)
        self._task = None

    def _cpu_seconds(self) -> float:
        t = self.p.cpu_times()
        return t.user + t.system

    async def _loop(self):
        self.p.cpu_percent(None)
        while True:
            await asyncio.sleep(0.2)
            self.samples.append((time.time(), self.p.cpu_percent(None),
                                 self.p.memory_info().rss / 2**20, self._cpu_seconds()))

    def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass

    def window(self, t0, t1):
        pts = [s for s in self.samples if t0 <= s[0] <= t1]
        cpu = [s[1] for s in pts] or [0.0]
        ram = [s[2] for s in pts] or [0.0]
        # CPU realmente consumida en la ventana (segundos de procesador), más fiable que el % medio
        cpu_s = (pts[-1][3] - pts[0][3]) if len(pts) >= 2 else 0.0
        return {"cpu_avg": statistics.fmean(cpu), "cpu_peak": max(cpu), "ram_peak_mb": max(ram),
                "cpu_seconds": cpu_s}


# ------------------------------------------------------------------- cliente
async def session(user, role, mode, port, ctx, gate, ready, results):
    r = {"user": user, "ok": False}
    reader = writer = None
    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.open_connection(
            config.HOST, port, ssl=ctx, server_hostname=config.SERVER_HOSTNAME if ctx else None)
        r["connect_ms"] = (time.perf_counter() - t0) * 1000
        if ctx:
            so = writer.get_extra_info("ssl_object")
            r["tls"], r["cipher"] = so.version(), so.cipher()[0]

        t1 = time.perf_counter()
        await asend_frame(writer, {"op": "LOGIN", "username": user, "password": config.PRELOAD_PASSWORD})
        reply = await arecv_frame(reader)
        r["login_ms"] = (time.perf_counter() - t1) * 1000
        if reply.get("status") != "OK":
            r["error"] = f"login: {reply}"
            ready.append(r)
            return
        ready.append(r)          # "estoy dentro"
        await gate.wait()        # barrera: nadie envía hasta que los 300 están conectados

        small, big = [], []
        payload_s, payload_b = "x" * SMALL_BYTES, "y" * BIG_BYTES
        for _ in range(SMALL_COUNT):
            t = time.perf_counter()
            await asend_frame(writer, {"op": "MSG", "data": payload_s})
            await arecv_frame(reader)
            small.append((time.perf_counter() - t) * 1000)
        r["msg_start"] = time.time()
        for _ in range(BIG_COUNT):
            t = time.perf_counter()
            await asend_frame(writer, {"op": "MSG", "data": payload_b})
            await arecv_frame(reader)
            big.append((time.perf_counter() - t) * 1000)
        r["small_ms"], r["big_ms"] = small, big
        r["bytes"] = BIG_COUNT * BIG_BYTES * 2  # ida y vuelta (eco)

        await asend_frame(writer, {"op": "LOGOUT"})
        await arecv_frame(reader)
        r["ok"] = True
    except Exception as exc:  # noqa: BLE001 - queremos contar cualquier fallo
        r["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        results.append(r)


async def unloaded_connect_ms(mode: str, port: int, user: str, ctx, n: int = 20) -> dict:
    """Coste de UN handshake sin competencia (conexiones una tras otra): separa el coste
    criptográfico puro del efecto "avalancha" de 300 conexiones a la vez."""
    times = []
    for _ in range(n):
        t = time.perf_counter()
        _, w = await asyncio.open_connection(
            config.HOST, port, ssl=ctx, server_hostname=config.SERVER_HOSTNAME if ctx else None)
        times.append((time.perf_counter() - t) * 1000)
        w.close()
        await w.wait_closed()
    return summarize(times)


async def run_once(mode: str, n_sessions: int, port: int) -> dict:
    server = start_server(mode, port)
    try:
        users = preload_names(n_sessions // len(config.ROLES))[:n_sessions]
        ctxs = [build_client_context(u) if mode == "tls" else None for u, _ in users]
        idle_ram = psutil.Process(server.pid).memory_info().rss / 2**20
        unloaded = await unloaded_connect_ms(mode, port, users[0][0], ctxs[0])
        sampler = ResourceSampler(server.pid)
        sampler.start()
        gate, ready, results = asyncio.Event(), [], []

        cpu_start = sampler._cpu_seconds()
        t_start = time.time()
        tasks = [asyncio.ensure_future(session(u, r, mode, port, c, gate, ready, results))
                 for (u, r), c in zip(users, ctxs)]
        while len(ready) < n_sessions and not all(t.done() for t in tasks):
            await asyncio.sleep(0.05)
        t_all_in = time.time()
        print(f"[BENCH]   {mode}: sesiones dentro en {t_all_in - t_start:.0f} s, enviando mensajes...", flush=True)
        simultaneous = sum(1 for r in ready if "error" not in r)
        cpu_gate = sampler._cpu_seconds()  # CPU gastada hasta tener las N sesiones dentro
        gate.set()
        await asyncio.gather(*tasks)
        t_end = time.time()
        cpu_end = sampler._cpu_seconds()
        await sampler.stop()

        ok = [r for r in results if r["ok"]]
        errors = [r["error"] for r in results if not r["ok"]][:5]
        msg_time = max(t_end - t_all_in, 1e-9)
        total_bytes = sum(r["bytes"] for r in ok)
        total_msgs = sum(len(r["small_ms"]) + len(r["big_ms"]) for r in ok)
        result = {
            "mode": mode, "sessions": n_sessions, "ok": len(ok), "failed": n_sessions - len(ok),
            "simultaneous_sessions": simultaneous, "errors": errors,
            "tls_version": next((r["tls"] for r in ok if "tls" in r), None),
            "cipher": next((r["cipher"] for r in ok if "cipher" in r), None),
            "connect_unloaded_ms": unloaded,
            "connect_ms": summarize([r["connect_ms"] for r in ok]),
            "login_ms": summarize([r["login_ms"] for r in ok]),
            "rtt_small_ms": summarize([x for r in ok for x in r["small_ms"]]),
            "rtt_big_ms": summarize([x for r in ok for x in r["big_ms"]]),
            "setup_seconds": t_all_in - t_start, "transfer_seconds": msg_time,
            "throughput_MBps": total_bytes / 2**20 / msg_time,
            "msgs_per_s": total_msgs / msg_time,
            "sessions_per_s": len(ok) / (t_end - t_start),
            "server_idle_ram_mb": idle_ram,
            "setup_phase": sampler.window(t_start, t_all_in),
            "transfer_phase": sampler.window(t_all_in, t_end),
        }
        # CPU exacta (contadores del proceso al abrir y cerrar cada fase), no muestreada
        result["cpu_s_setup"] = cpu_gate - cpu_start
        result["cpu_s_transfer"] = cpu_end - cpu_gate
        result["cpu_ms_per_MB"] = result["cpu_s_transfer"] * 1000 / max(total_bytes / 2**20, 1e-9)
        return result
    finally:
        server.terminate()
        try:
            server.wait(5)
        except subprocess.TimeoutExpired:
            server.kill()


def median_run(runs: list[dict]) -> dict:
    """Devuelve la ejecución con mediana de throughput (representativa y con todos sus campos)."""
    return sorted(runs, key=lambda r: r["throughput_MBps"])[len(runs) // 2]


def overhead(tls: dict, plain: dict) -> dict:
    def rel(a, b):
        return (a - b) / b * 100 if b else float("nan")
    return {
        "connect_unloaded_p50_ms": [plain["connect_unloaded_ms"]["p50"], tls["connect_unloaded_ms"]["p50"]],
        "connect_p50_ms": [plain["connect_ms"]["p50"], tls["connect_ms"]["p50"]],
        "rtt_small_p50_ms": [plain["rtt_small_ms"]["p50"], tls["rtt_small_ms"]["p50"]],
        "rtt_big_p50_ms": [plain["rtt_big_ms"]["p50"], tls["rtt_big_ms"]["p50"]],
        "throughput_MBps": [plain["throughput_MBps"], tls["throughput_MBps"]],
        "server_cpu_avg_transfer": [plain["transfer_phase"]["cpu_avg"], tls["transfer_phase"]["cpu_avg"]],
        "server_ram_peak_mb": [plain["transfer_phase"]["ram_peak_mb"], tls["transfer_phase"]["ram_peak_mb"]],
        "pct": {
            "connect_unloaded": rel(tls["connect_unloaded_ms"]["p50"], plain["connect_unloaded_ms"]["p50"]),
            "connect_latency": rel(tls["connect_ms"]["p50"], plain["connect_ms"]["p50"]),
            "rtt_small": rel(tls["rtt_small_ms"]["p50"], plain["rtt_small_ms"]["p50"]),
            "throughput": rel(tls["throughput_MBps"], plain["throughput_MBps"]),
            "cpu": rel(tls["transfer_phase"]["cpu_avg"], plain["transfer_phase"]["cpu_avg"]),
            "cpu_per_mb": rel(tls["cpu_ms_per_MB"], plain["cpu_ms_per_MB"]),
            "cpu_setup": rel(tls["cpu_s_setup"], plain["cpu_s_setup"]),
            "ram": rel(tls["transfer_phase"]["ram_peak_mb"], plain["transfer_phase"]["ram_peak_mb"]),
        },
    }


def print_report(tls, plain, ov):
    print("\n" + "=" * 70)
    print(f" BENCHMARK {tls['sessions']} SESIONES SIMULTÁNEAS  (sesiones abiertas a la vez: "
          f"TLS={tls['simultaneous_sessions']}, plano={plain['simultaneous_sessions']})")
    print("=" * 70)
    print(f" {'métrica':<34}{'PLANO':>12}{'TLS1.3+mTLS':>14}{'overhead':>10}")
    rows = [
        ("OK / fallidas", f"{plain['ok']}/{plain['failed']}", f"{tls['ok']}/{tls['failed']}", ""),
        ("Handshake sin carga p50 (ms)", f"{plain['connect_unloaded_ms']['p50']:.1f}", f"{tls['connect_unloaded_ms']['p50']:.1f}", f"{ov['pct']['connect_unloaded']:+.0f}%"),
        (f"Conexión con {tls['sessions']} a la vez p50 (ms)", f"{plain['connect_ms']['p50']:.1f}", f"{tls['connect_ms']['p50']:.1f}", f"{ov['pct']['connect_latency']:+.0f}%"),
        ("RTT 256 B p50 (ms)", f"{plain['rtt_small_ms']['p50']:.2f}", f"{tls['rtt_small_ms']['p50']:.2f}", f"{ov['pct']['rtt_small']:+.0f}%"),
        ("RTT 256 B p95 (ms)", f"{plain['rtt_small_ms']['p95']:.2f}", f"{tls['rtt_small_ms']['p95']:.2f}", ""),
        ("RTT 256 B p99 (ms)", f"{plain['rtt_small_ms']['p99']:.2f}", f"{tls['rtt_small_ms']['p99']:.2f}", ""),
        ("Throughput (MB/s)", f"{plain['throughput_MBps']:.1f}", f"{tls['throughput_MBps']:.1f}", f"{ov['pct']['throughput']:+.0f}%"),
        ("Mensajes/s", f"{plain['msgs_per_s']:.0f}", f"{tls['msgs_per_s']:.0f}", ""),
        (f"CPU del servidor en conectar {tls['sessions']} (s)", f"{plain['cpu_s_setup']:.1f}", f"{tls['cpu_s_setup']:.1f}", f"{ov['pct']['cpu_setup']:+.0f}%"),
        ("CPU del servidor por MB (ms/MB)", f"{plain['cpu_ms_per_MB']:.0f}", f"{tls['cpu_ms_per_MB']:.0f}", f"{ov['pct']['cpu_per_mb']:+.0f}%"),
        ("CPU media (% de un núcleo, orientativa)", f"{plain['transfer_phase']['cpu_avg']:.0f}", f"{tls['transfer_phase']['cpu_avg']:.0f}", f"{ov['pct']['cpu']:+.0f}%"),
        ("RAM servidor pico (MB)", f"{plain['transfer_phase']['ram_peak_mb']:.0f}", f"{tls['transfer_phase']['ram_peak_mb']:.0f}", f"{ov['pct']['ram']:+.0f}%"),
    ]
    for name, a, b, c in rows:
        print(f" {name:<34}{a:>12}{b:>14}{c:>10}")
    print(f" Protocolo negociado: {tls['tls_version']} / {tls['cipher']}")
    print("=" * 70)


async def main_async(args):
    all_runs = {"plain": [], "tls": []}
    for i in range(args.runs):
        for mode, port in (("plain", args.plain_port), ("tls", args.tls_port)):
            print(f"[BENCH] run {i + 1}/{args.runs} modo={mode} ...", flush=True)
            all_runs[mode].append(await run_once(mode, args.sessions, port))
            await asyncio.sleep(1)  # que el SO libere puertos
    tls, plain = median_run(all_runs["tls"]), median_run(all_runs["plain"])
    ov = overhead(tls, plain)
    out = {"sessions": args.sessions, "runs": args.runs, "tls": tls, "plain": plain, "overhead": ov,
           "all_runs": all_runs,
           "environment": {"cpus": os.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
                           "python": sys.version.split()[0], "os": sys.platform,
                           "note": "cliente y servidor en la misma máquina (loopback)"}}
    config.BENCH_DIR.mkdir(parents=True, exist_ok=True)
    (config.BENCH_DIR / "benchmark_results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print_report(tls, plain, ov)
    try:
        from benchmarks.plot import make_plots
        make_plots(out)
    except ImportError:
        pass
    return out


def run_300_benchmark(sessions: int = 300, runs: int = 3):
    """Atajo para el menú principal."""
    ns = argparse.Namespace(sessions=sessions, runs=runs, tls_port=18443, plain_port=18080)
    return asyncio.run(main_async(ns))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # informe legible también al redirigir a fichero en Windows
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=300)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--tls-port", type=int, default=18443)
    ap.add_argument("--plain-port", type=int, default=18080)
    asyncio.run(main_async(ap.parse_args()))
