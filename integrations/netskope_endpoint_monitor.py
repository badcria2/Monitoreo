# C:\netskope-wazuh\integrations\netskope_endpoint_monitor.py
import os
import requests
import json
import logging
import time
from datetime import datetime, timedelta, timezone

# --- Configuración ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Variables de Entorno ---
NETSKOPE_TENANT_URL = os.getenv('NETSKOPE_TENANT_URL')
NETSKOPE_API_TOKEN = os.getenv('NETSKOPE_API_TOKEN')
# Dejamos un intervalo corto para pruebas, luego puedes subirlo
MONITOR_INTERVAL_SECONDS = int(os.getenv('MONITOR_INTERVAL_SECONDS', 300)) 

# --- Configuración de Wazuh ---
WAZUH_MANAGER_HOST = 'wazuh.manager'
WAZUH_MANAGER_PORT = 1514

# --- Variable para guardar el timestamp de la última ejecución ---
last_run_timestamp = None

def send_log_to_wazuh(log_message):
    """Envía un log en formato JSON al socket de Wazuh."""
    try:
        import socket
        wazuh_msg = f'<134>1 {datetime.now(timezone.utc).isoformat()} {socket.gethostname()} netskope_monitor - - - {json.dumps(log_message)}'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(wazuh_msg.encode('utf-8'), (WAZUH_MANAGER_HOST, WAZUH_MANAGER_PORT))
        logging.info(f"Sent log to Wazuh for event type: {log_message.get('type', 'N/A')}")
    except Exception as e:
        logging.error(f"Failed to send log to Wazuh: {e}")

def fetch_netskope_status_events(start_time, end_time):
    """Obtiene eventos de estado del cliente desde la API de Netskope."""
    headers = {'Netskope-Api-Token': NETSKOPE_API_TOKEN}
    url = f"{NETSKOPE_TENANT_URL}/api/v2/events/datasearch/clientstatus"
    
    # --- CAMBIO CLAVE #1: Los parámetros van en un diccionario 'params' para una petición GET ---
    params = {
        "starttime": int(start_time.timestamp()),
        "endtime": int(end_time.timestamp()),
        "limit": 1000 # Un límite razonable para cada consulta
    }
    
    logging.info(f"Fetching client status events using GET with params: {params}")
    try:
        # --- CAMBIO CLAVE #2: Usamos requests.get() y pasamos el diccionario a 'params' ---
        response = requests.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        data = response.json().get('data', [])
        logging.info(f"Successfully fetched {len(data)} events.")
        return data
    except requests.exceptions.RequestException as e:
        # Imprimimos el texto de la respuesta si es un error del cliente para más detalles
        if e.response is not None:
            logging.error(f"Error fetching data from Netskope API: {e} - Response: {e.response.text}")
        else:
            logging.error(f"Error fetching data from Netskope API: {e}")
        return None

def main():
    """Función principal del monitor."""
    global last_run_timestamp
    logging.info("Starting Netskope Endpoint Monitor cycle...")
    
    if not all([NETSKOPE_TENANT_URL, NETSKOPE_API_TOKEN]):
        logging.error("Netskope environment variables are not set. Exiting cycle.")
        return

    end_time = datetime.now(timezone.utc)
    if last_run_timestamp is None:
        start_time = end_time - timedelta(seconds=MONITOR_INTERVAL_SECONDS)
    else:
        # Sumamos 1 segundo para evitar traer el último evento de la corrida anterior
        start_time = last_run_timestamp + timedelta(seconds=1)

    events = fetch_netskope_status_events(start_time, end_time)

    if events is not None:
        for event in events:
            log_payload = {
                "type": event.get('type'),
                "user": event.get('user', 'N/A'),
                "hostname": event.get('hostname', 'N/A'),
                "client_version": event.get('client_version', 'N/A'),
                "os": event.get('os_name', 'N/A'),
                "original_event": event
            }
            send_log_to_wazuh(log_payload)
    
    last_run_timestamp = end_time
    logging.info("Monitoring cycle finished.")


if __name__ == "__main__":
    while True:
        main()
        logging.info(f"Sleeping for {MONITOR_INTERVAL_SECONDS} seconds...")
        time.sleep(MONITOR_INTERVAL_SECONDS)