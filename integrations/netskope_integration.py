#!/usr/bin/env python3
"""
Netskope to Wazuh Integration Script
Monitors Netskope client status and sends events to Wazuh
"""

import os
import sys
import json
import time
import logging
import socket
import requests
import schedule
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
class Config:
    def __init__(self):
        # Environment variables
        self.netskope_tenant = os.getenv('NETSKOPE_TENANT', '')
        self.netskope_token = os.getenv('NETSKOPE_TOKEN', '')
        self.wazuh_manager_host = os.getenv('WAZUH_MANAGER_HOST', 'wazuh-manager')
        self.wazuh_manager_port = int(os.getenv('WAZUH_MANAGER_PORT', '1514'))
        self.poll_interval = int(os.getenv('POLL_INTERVAL', '300'))  # 5 minutes
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        
        # File paths
        self.log_dir = '/var/log/netskope-wazuh'
        self.config_file = '/app/config.json'
        
        # Load additional config from file
        self.load_config_file()
        
        # API endpoints
        self.api_base = f"https://{self.netskope_tenant}/api/v2"
        self.client_events_endpoint = f"{self.api_base}/events/dataexport/events/endpoint"
        self.alert_events_endpoint = f"{self.api_base}/events/dataexport/events/alert"
        self.audit_events_endpoint = f"{self.api_base}/events/dataexport/events/audit"
        
    def load_config_file(self):
        """Load additional configuration from JSON file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                    # Override with file values if present
                    for key, value in config_data.items():
                        if hasattr(self, key):
                            setattr(self, key, value)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")

# Logging setup
def setup_logging(config: Config):
    """Setup logging configuration"""
    os.makedirs(config.log_dir, exist_ok=True)
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper()),
        format=log_format,
        handlers=[
            logging.FileHandler(f'{config.log_dir}/netskope_integration.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

class WazuhSender:
    """Handles sending events to Wazuh manager"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.socket = None
        
    def connect(self):
        """Connect to Wazuh manager"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.config.wazuh_manager_host, self.config.wazuh_manager_port))
            self.logger.info(f"Connected to Wazuh manager at {self.config.wazuh_manager_host}:{self.config.wazuh_manager_port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Wazuh manager: {e}")
            return False
    
    def send_event(self, event_data: Dict[str, Any], event_type: str = "client_status"):
        """Send event to Wazuh manager"""
        try:
            # Format event for Wazuh
            wazuh_event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "integration": "netskope",
                "netskope": event_type,
                "event_type": event_type,
                **event_data
            }
            
            # Convert to JSON string
            event_json = json.dumps(wazuh_event)
            
            # Send to Wazuh
            if not self.socket:
                if not self.connect():
                    return False
            
            try:
                self.socket.send(f"{event_json}\n".encode('utf-8'))
                self.logger.debug(f"Sent event to Wazuh: {event_type}")
                
                # Also write to log file for backup
                self.write_to_log_file(wazuh_event, event_type)
                return True
                
            except (BrokenPipeError, ConnectionResetError):
                self.logger.warning("Connection to Wazuh lost, attempting to reconnect...")
                self.socket = None
                if self.connect():
                    self.socket.send(f"{event_json}\n".encode('utf-8'))
                    self.write_to_log_file(wazuh_event, event_type)
                    return True
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending event to Wazuh: {e}")
            return False
    
    def write_to_log_file(self, event_data: Dict[str, Any], event_type: str):
        """Write event to log file as backup"""
        try:
            log_file = f"{self.config.log_dir}/netskope_{event_type}.log"
            with open(log_file, 'a') as f:
                f.write(json.dumps(event_data) + '\n')
        except Exception as e:
            self.logger.error(f"Error writing to log file: {e}")
    
    def close(self):
        """Close connection to Wazuh manager"""
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("Closed connection to Wazuh manager")
            except Exception as e:
                self.logger.error(f"Error closing Wazuh connection: {e}")

class NetskopeFetcher:
    """Handles fetching data from Netskope API"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'Netskope-Api-Token': config.netskope_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Track last fetch times
        self.last_fetch_times = {
            'client_events': None,
            'alerts': None,
            'audit': None
        }
        
    def get_client_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch client events from Netskope API"""
        try:
            params = {
                'starttime': int(start_time.timestamp()),
                'endtime': int(end_time.timestamp()),
                'skip': 0,
                'limit': 5000
            }
            
            response = self.session.get(
                self.config.client_events_endpoint,
                params=params,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('data', [])
                self.logger.info(f"Fetched {len(events)} client events")
                return events
            elif response.status_code == 429:
                self.logger.warning("Rate limit reached, waiting...")
                time.sleep(60)
                return []
            else:
                self.logger.error(f"API request failed: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error fetching client events: {e}")
            return []
    
    def get_alert_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch alert events from Netskope API"""
        try:
            params = {
                'starttime': int(start_time.timestamp()),
                'endtime': int(end_time.timestamp()),
                'skip': 0,
                'limit': 5000,
                'type': 'all'
            }
            
            response = self.session.get(
                self.config.alert_events_endpoint,
                params=params,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('data', [])
                self.logger.info(f"Fetched {len(events)} alert events")
                return events
            elif response.status_code == 429:
                self.logger.warning("Rate limit reached, waiting...")
                time.sleep(60)
                return []
            else:
                self.logger.error(f"Alert API request failed: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error fetching alert events: {e}")
            return []

    def get_audit_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch audit events from Netskope API"""
        try:
            params = {
                'starttime': int(start_time.timestamp()),
                'endtime': int(end_time.timestamp()),
                'skip': 0,
                'limit': 5000
            }
            
            response = self.session.get(
                self.config.audit_events_endpoint,
                params=params,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('data', [])
                self.logger.info(f"Fetched {len(events)} audit events")
                return events
            elif response.status_code == 429:
                self.logger.warning("Rate limit reached, waiting...")
                time.sleep(60)
                return []
            else:
                self.logger.error(f"Audit API request failed: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error fetching audit events: {e}")
            return []

class NetskopeMon:
    """Main integration class"""
    
    def __init__(self):
        self.config = Config()
        self.logger = setup_logging(self.config)
        self.wazuh_sender = WazuhSender(self.config, self.logger)
        self.netskope_fetcher = NetskopeFetcher(self.config, self.logger)
        self.running = True
        
        # Validate configuration
        if not self.config.netskope_tenant or not self.config.netskope_token:
            self.logger.error("Missing Netskope configuration. Check NETSKOPE_TENANT and NETSKOPE_TOKEN environment variables.")
            sys.exit(1)
    
    def process_client_events(self):
        """Process and send client events to Wazuh"""
        self.logger.info("Processing client events...")
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(seconds=self.config.poll_interval + 60)  # Add buffer
        
        events = self.netskope_fetcher.get_client_events(start_time, end_time)
        
        for event in events:
            # Process and normalize event data
            normalized_event = self.normalize_client_event(event)
            
            # Send to Wazuh
            success = self.wazuh_sender.send_event(normalized_event, "client_events")
            
            if not success:
                self.logger.warning(f"Failed to send client event: {event.get('_id', 'unknown')}")
    
    def process_alert_events(self):
        """Process and send alert events to Wazuh"""
        self.logger.info("Processing alert events...")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(seconds=self.config.poll_interval + 60)
        
        events = self.netskope_fetcher.get_alert_events(start_time, end_time)
        
        for event in events:
            normalized_event = self.normalize_alert_event(event)
            success = self.wazuh_sender.send_event(normalized_event, "alerts")
            
            if not success:
                self.logger.warning(f"Failed to send alert event: {event.get('_id', 'unknown')}")
    
    def normalize_client_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize client event data for Wazuh"""
        return {
            "event_id": event.get("_id"),
            "timestamp": event.get("timestamp"),
            "hostname": event.get("hostname", event.get("device_name")),
            "user": event.get("user", event.get("username")),
            "device_id": event.get("device_id"),
            "client_version": event.get("client_version"),
            "client_status": event.get("status", event.get("client_status")),
            "tunnel_status": event.get("tunnel_status"),
            "installation_status": event.get("installation_status"),
            "upgrade_status": event.get("upgrade_status"),
            "client_action": event.get("action"),
            "initiated_by": event.get("initiated_by"),
            "policy_violation": event.get("policy_violation", False),
            "policy_name": event.get("policy_name"),
            "auth_status": event.get("auth_status"),
            "version_status": event.get("version_status"),
            "last_seen": event.get("last_seen"),
            "ip_address": event.get("srcip", event.get("ip_address")),
            "mac_address": event.get("mac_address"),
            "os_version": event.get("os_version", event.get("os")),
            "event_subtype": event.get("event_subtype", event.get("type")),
            "location": event.get("location"),
            "raw_event": json.dumps(event)
        }
    
    def normalize_alert_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize alert event data for Wazuh"""
        return {
            "event_id": event.get("_id"),
            "alert_id": event.get("alert_id"),
            "timestamp": event.get("timestamp"),
            "alert_type": event.get("alert_type", event.get("type")),
            "alert_name": event.get("alert_name", event.get("alertname")),
            "severity": event.get("severity"),
            "user": event.get("user", event.get("username")),
            "hostname": event.get("hostname", event.get("device_name")),
            "device_id": event.get("device_id"),
            "policy_name": event.get("policy"),
            "app_name": event.get("app", event.get("application")),
            "activity": event.get("activity"),
            "category": event.get("category"),
            "source_ip": event.get("srcip"),
            "destination_ip": event.get("dstip"),
            "url": event.get("url"),
            "file_name": event.get("file"),
            "file_size": event.get("file_size"),
            "threat_name": event.get("threat_name"),
            "risk_level": event.get("risk_level"),
            "raw_event": json.dumps(event)
        }
    
    def run_polling_cycle(self):
        """Run a complete polling cycle"""
        try:
            self.logger.info("Starting polling cycle...")
            
            # Process different event types
            self.process_client_events()
            self.process_alert_events()
            
            self.logger.info("Polling cycle completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error in polling cycle: {e}")
    
    def run(self):
        """Main run loop"""
        self.logger.info("Starting Netskope integration...")
        self.logger.info(f"Polling interval: {self.config.poll_interval} seconds")
        
        # Connect to Wazuh
        if not self.wazuh_sender.connect():
            self.logger.error("Failed to connect to Wazuh manager")
            sys.exit(1)
        
        # Schedule polling
        schedule.every(self.config.poll_interval).seconds.do(self.run_polling_cycle)
        
        # Run initial poll
        self.run_polling_cycle()
        
        # Main loop
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal, stopping...")
                self.running = False
            except Exception as e:
                self.logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(10)  # Wait before retrying
        
        # Cleanup
        self.wazuh_sender.close()
        self.logger.info("Integration stopped")

if __name__ == "__main__":
    try:
        integration = NetskopeMon()
        integration.run()
    except Exception as e:
        print(f"Fatal error starting integration: {e}")
        sys.exit(1)