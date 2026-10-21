import asyncio
import json
import os
import ssl
import time
import psutil

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")

def get_benchmark_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    ca_crt = os.path.join(BASE_DIR, "certs", "ca", "ca.crt")
    cli_crt = os.path.join(BASE_DIR, "certs", "clients", "pdi_user1", "pdi_user1.crt")
    cli_key = os.path.join(BASE_DIR, "certs", "clients", "pdi_user1", "pdi_user1.key")

    ctx.load_verify_locations(cafile=ca_crt)
    ctx.load_cert_chain(certfile=cli_crt, keyfile=cli_key)
    ctx.check_hostname = False
    return ctx

async def simulate_user_session(user_id, ctx, host="127.0.0.1", port=8443):
    start_t = time.time()
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ctx, server_hostname="gateway.usecure.es")
        
        # Enviar autenticación
        auth_msg = json.dumps({"username": "pdi_user1", "password": "Password123!"})
        writer.write(auth_msg.encode('utf-8'))
        await writer.drain()

        auth_res = await reader.read(1024)

        # Enviar payload
        writer.write(f"USER_{user_id}_BENCHMARK_PAYLOAD".encode('utf-8'))
        await writer.drain()

        reply = await reader.read(1024)

        # Logout explícito
        writer.write(b"LOGOUT")
        await writer.drain()
        await reader.read(1024)

        writer.close()
        await writer.wait_closed()
        
        rtt = time.time() - start_t
        return {"id": user_id, "status": "OK", "rtt": rtt}
    except Exception as e:
        return {"id": user_id, "status": "ERROR", "error": str(e)}

async def run_300_benchmark():
    print("==================================================")
    print("  PRUEBA DE ESCALABILIDAD Y BENCHMARK (300 USERS)  ")
    print("==================================================")
    
    ctx = get_benchmark_ssl_context()
    
    # Monitorizar recursos iniciales
    cpu_init = psutil.cpu_percent(interval=None)
    ram_init = psutil.virtual_memory().used / (1024 * 1024)

    start_total = time.time()
    tasks = [simulate_user_session(i, ctx) for i in range(300)]
    results = await asyncio.gather(*tasks)
    total_time = time.time() - start_total

    # Monitorizar recursos finales
    cpu_end = psutil.cpu_percent(interval=None)
    ram_end = psutil.virtual_memory().used / (1024 * 1024)

    successful = [r for r in results if r["status"] == "OK"]
    failed = [r for r in results if r["status"] == "ERROR"]
    rtts = [r["rtt"] for r in successful]

    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
    throughput = len(successful) / total_time

    print(f"Sesiones Exitosas: {len(successful)} / 300")
    print(f"Sesiones Fallidas:  {len(failed)}")
    print(f"Tiempo Total:       {total_time:.2f} segundos")
    print(f"Throughput:         {throughput:.2f} req/seg")
    print(f"Latencia Media RTT: {avg_rtt * 1000:.2f} ms")
    print(f"Consumo de RAM:     +{ram_end - ram_init:.2f} MB")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_300_benchmark())