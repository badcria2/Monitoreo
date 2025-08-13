#!/usr/bin/env python3
"""
Netskope Endpoint Monitor
Specifically monitors endpoint status changes and generates alerts for disconnected/uninstalled clients
"""

import os
import sys
import json
import time
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class EndpointStatus:
    """Represents the status of a Netskope client endpoint"""
    device_id: str
    hostname: str
    user: str
    client_version: str
    status: str  # connected, disconnected, uninstalled
    last_seen: datetime
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_version: Optional[str] = None
    tunnel_status: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['last_seen'] = self.last_seen.isoformat() if isinstance(self.last_seen, datetime) else self.last_seen
        return data

class EndpointTracker:
    """Tracks endpoint states and detects changes"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.known_endpoints: Dict[str, EndpointStatus] = {}
        self.state_file = '/var/log/netskope-wazuh/endpoint_states.json'
        self.load_state()
    
    def load_state(self):
        """Load previous endpoint states from file"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    for device_id, endpoint_data in data.items():
                        # Convert last_seen back to datetime
                        if endpoint_data.get('last_seen'):
                            endpoint_data['last_seen'] = datetime.fromisoformat(
                                endpoint_data['last_seen'].replace('Z', '+00:00')
                            )
                        else:
                            endpoint_data['last_seen'] = datetime.utcnow()
                        
                        self.known_endpoints[device_id] = EndpointStatus(**endpoint_data)
                self.logger.info(f"Loaded {len(self.known_endpoints)} known endpoints")
        except Exception as e:
            self.logger.warning(f"Could not load endpoint states: {e}")
    
    def save_state(self):
        """Save current endpoint states to file"""
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                state_data = {device_id: endpoint.to_dict() 
                            for device_id, endpoint in self.known_endpoints.items()}
                json.dump(state_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Could not save endpoint states: {e}")
    
    def update_endpoints(self, current_endpoints: List[EndpointStatus]) -> List[Dict[str, any]]:
        """Update endpoint states and return list of state changes"""
        changes = []
        current_device_ids = set()
        
        # Process current endpoints
        for endpoint in current_endpoints:
            current_device_ids.add(endpoint.device_id)
            previous = self.known_endpoints.get(endpoint.device_id)
            
            if not previous:
                # New endpoint discovered
                changes.append({
                    'change_type': 'new_endpoint',
                    'device_id': endpoint.device_id,
                    'hostname': endpoint.hostname,
                    'user': endpoint.user,
                    'status': endpoint.status,
                    'client_version': endpoint.client_version,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
                self.logger.info(f"New endpoint discovered: {endpoint.hostname} ({endpoint.device_id})")
            
            elif previous.status != endpoint.status:
                # Status change detected
                changes.append({
                    'change_type': 'status_change',
                    'device_id': endpoint.device_id,
                    'hostname': endpoint.hostname,
                    'user': endpoint.user,
                    'previous_status': previous.status,
                    'new_status': endpoint.status,
                    'client_version': endpoint.client_version,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
                self.logger.info(f"Status change for {endpoint.hostname}: {previous.status} -> {endpoint.status}")
            
            elif previous.client_version != endpoint.client_version:
                # Version change detected
                changes.append({
                    'change_type': 'version_change',
                    'device_id': endpoint.device_id,
                    'hostname': endpoint.hostname,
                    'user': endpoint.user,
                    'previous_version': previous.client_version,
                    'new_version': endpoint.client_version,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
                self.logger.info(f"Version change for {endpoint.hostname}: {previous.client_version} -> {endpoint.client_version}")
            
            # Update known endpoints
            self.known_endpoints[endpoint.device_id] = endpoint
        
        # Check for missing endpoints (potentially uninstalled or offline)
        cutoff_time = datetime.utcnow() - timedelta(minutes=30)  # Consider offline after 30 minutes
        
        for device_id, endpoint in list(self.known_endpoints.items()):
            if device_id not in current_device_ids:
                if endpoint.status != 'missing' and endpoint.last_seen > cutoff_time:
                    # Recently seen endpoint is now missing
                    changes.append({
                        'change_type': 'endpoint_missing',
                        'device_id': endpoint.device_id,
                        'hostname': endpoint.hostname,
                        'user': endpoint.user,
                        'last_status': endpoint.status,
                        'last_seen': endpoint.last_seen.isoformat() + 'Z',
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    })
                    self.logger.warning(f"Endpoint missing: {endpoint.hostname} ({endpoint.device_id})")
                    
                    # Update status to missing
                    endpoint.status = 'missing'
                    self.known_endpoints[device_id] = endpoint
                
                elif endpoint.last_seen < datetime.utcnow() - timedelta(hours=24):
                    # Remove very old entries
                    del self.known_endpoints[device_id]
                    self.logger.info(f"Removed stale endpoint: {endpoint.hostname}")
        
        # Save updated state
        self.save_state()
        
        return changes

class EndpointMonitor:
    """Main endpoint monitoring class"""
    
    def __init__(self):
        # Setup logging
        self.setup_logging()
        
        # Configuration
        self.netskope_tenant = os.getenv('NETSKOPE_TENANT', '')
        self.netskope_token = os.getenv('NETSKOPE_TOKEN', '')
        self.wazuh_manager_host = os.getenv('WAZUH_MANAGER_HOST', 'wazuh-manager')
        self.wazuh_manager_port = int(os.getenv('WAZUH_MANAGER_PORT', '1514'))
        
        if not self.netskope_tenant or not self.netskope_token:
            self.logger.error("Missing Netskope configuration")
            sys.exit(1)
        
        # Initialize components
        self.endpoint_tracker = EndpointTracker(self.logger)
        self.session = requests.Session()
        self.session.headers.update({
            'Netskope-Api-Token': self.netskope_token,
            'Content-Type': 'application/json'
        })
        
        # API endpoints
        self.api_base = f"https://{self.netskope_tenant}/api/v2"
        self.client_events_endpoint = f"{self.api_base}/events/dataexport/events/endpoint"
        
        # Import WazuhSender from main integration
        from netskope_integration import WazuhSender, Config
        config = Config()
        config.netskope_tenant = self.netskope_tenant
        config.netskope_token = self.netskope_token
        config.wazuh_manager_host = self.wazuh_manager_host
        config.wazuh_manager_port = self.wazuh_manager_port
        
        self.wazuh_sender = WazuhSender(config, self.logger)
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = '/var/log/netskope-wazuh'
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'{log_dir}/endpoint_monitor.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger('EndpointMonitor')
    
    def fetch_current_endpoints(self) -> List[EndpointStatus]:
        """Fetch current endpoint status from Netskope API"""
        endpoints = []
        
        try:
            # Get recent client events to determine current status
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)  # Look back 1 hour
            
            params = {
                'starttime': int(start_time.timestamp()),
                'endtime': int(end_time.timestamp()),
                'skip': 0,
                'limit': 5000
            }
            
            response = self.session.get(
                self.client_events_endpoint,
                params=params,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('data', [])
                self.logger.info(f"Fetched {len(events)} client events for status analysis")
                
                # Group events by device_id to get latest status
                device_events = {}
                for event in events:
                    device_id = event.get('device_id')
                    if not device_id:
                        continue
                    
                    event_time = datetime.fromtimestamp(event.get('timestamp', 0))
                    
                    if device_id not in device_events or event_time > device_events[device_id]['timestamp']:
                        device_events[device_id] = {
                            'timestamp': event_time,
                            'event': event
                        }
                
                # Convert to EndpointStatus objects
                for device_id, device_data in device_events.items():
                    event = device_data['event']
                    
                    # Determine status from event data
                    status = self.determine_endpoint_status(event)
                    
                    endpoint = EndpointStatus(
                        device_id=device_id,
                        hostname=event.get('hostname', event.get('device_name', 'Unknown')),
                        user=event.get('user', event.get('username', 'Unknown')),
                        client_version=event.get('client_version', 'Unknown'),
                        status=status,
                        last_seen=device_data['timestamp'],
                        ip_address=event.get('srcip', event.get('ip_address')),
                        mac_address=event.get('mac_address'),
                        os_version=event.get('os_version', event.get('os')),
                        tunnel_status=event.get('tunnel_status')
                    )
                    
                    endpoints.append(endpoint)
            
            elif response.status_code == 429:
                self.logger.warning("API rate limit reached")
                time.sleep(60)
            else:
                self.logger.error(f"API request failed: {response.status_code} - {response.text}")
        
        except Exception as e:
            self.logger.error(f"Error fetching current endpoints: {e}")
        
        return endpoints
    
    def determine_endpoint_status(self, event: Dict) -> str:
        """Determine endpoint status from event data"""
        # Check various status indicators
        client_status = event.get('status', event.get('client_status', '')).lower()
        tunnel_status = event.get('tunnel_status', '').lower()
        event_type = event.get('type', event.get('event_type', '')).lower()
        action = event.get('action', '').lower()
        
        # Priority-based status determination
        if 'uninstall' in event_type or 'uninstall' in action:
            return 'uninstalled'
        elif 'disconnect' in client_status or 'offline' in client_status or 'down' in tunnel_status:
            return 'disconnected'
        elif 'connect' in client_status or 'online' in client_status or 'up' in tunnel_status:
            return 'connected'
        elif 'install' in event_type and 'fail' in event_type:
            return 'installation_failed'
        elif 'upgrade' in event_type and 'fail' in event_type:
            return 'upgrade_failed'
        else:
            # Default based on tunnel status or assume connected if no clear indicator
            if tunnel_status == 'up':
                return 'connected'
            elif tunnel_status == 'down':
                return 'disconnected'
            else:
                return 'connected'  # Default assumption
    
    def send_status_alerts(self, changes: List[Dict]):
        """Send status change alerts to Wazuh"""
        if not self.wazuh_sender.connect():
            self.logger.error("Failed to connect to Wazuh manager")
            return
        
        for change in changes:
            # Create alert based on change type
            alert_data = {
                **change,
                'source': 'netskope_endpoint_monitor',
                'integration': 'netskope'
            }
            
            # Set alert level based on change type
            if change['change_type'] == 'endpoint_missing':
                alert_data['alert_level'] = 'high'
                alert_data['alert_description'] = f"Endpoint {change['hostname']} is missing/offline"
            elif change['change_type'] == 'status_change':
                if change['new_status'] in ['disconnected', 'uninstalled']:
                    alert_data['alert_level'] = 'high'
                    alert_data['alert_description'] = f"Endpoint {change['hostname']} status changed to {change['new_status']}"
                else:
                    alert_data['alert_level'] = 'medium'
                    alert_data['alert_description'] = f"Endpoint {change['hostname']} status changed to {change['new_status']}"
            else:
                alert_data['alert_level'] = 'low'
                alert_data['alert_description'] = f"Endpoint {change.get('hostname', 'unknown')} {change['change_type']}"
            
            # Send to Wazuh
            success = self.wazuh_sender.send_event(alert_data, "client_status")
            
            if success:
                self.logger.info(f"Sent alert for {change['change_type']}: {change.get('hostname', 'unknown')}")
            else:
                self.logger.error(f"Failed to send alert for {change['change_type']}")
    
    def generate_status_report(self, endpoints: List[EndpointStatus]):
        """Generate and send periodic status report"""
        try:
            # Count endpoints by status
            status_counts = {}
            for endpoint in endpoints:
                status = endpoint.status
                status_counts[status] = status_counts.get(status, 0) + 1
            
            # Create summary report
            report = {
                'report_type': 'endpoint_status_summary',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'total_endpoints': len(endpoints),
                'status_breakdown': status_counts,
                'source': 'netskope_endpoint_monitor',
                'integration': 'netskope'
            }
            
            # Send report to Wazuh
            success = self.wazuh_sender.send_event(report, "client_status")
            
            if success:
                self.logger.info(f"Sent status report: {len(endpoints)} total endpoints")
            else:
                self.logger.error("Failed to send status report")
        
        except Exception as e:
            self.logger.error(f"Error generating status report: {e}")
    
    def check_stale_endpoints(self):
        """Check for endpoints that haven't been seen recently"""
        cutoff_time = datetime.utcnow() - timedelta(hours=6)  # 6 hours without activity
        stale_endpoints = []
        
        for device_id, endpoint in self.endpoint_tracker.known_endpoints.items():
            if endpoint.last_seen < cutoff_time and endpoint.status not in ['missing', 'uninstalled']:
                stale_endpoints.append({
                    'change_type': 'stale_endpoint',
                    'device_id': endpoint.device_id,
                    'hostname': endpoint.hostname,
                    'user': endpoint.user,
                    'status': endpoint.status,
                    'last_seen': endpoint.last_seen.isoformat() + 'Z',
                    'hours_since_seen': int((datetime.utcnow() - endpoint.last_seen).total_seconds() / 3600),
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
        
        if stale_endpoints:
            self.logger.warning(f"Found {len(stale_endpoints)} stale endpoints")
            self.send_status_alerts(stale_endpoints)
    
    def run_monitoring_cycle(self):
        """Run a complete monitoring cycle"""
        try:
            self.logger.info("Starting endpoint monitoring cycle...")
            
            # Fetch current endpoint status
            current_endpoints = self.fetch_current_endpoints()
            self.logger.info(f"Found {len(current_endpoints)} current endpoints")
            
            # Update endpoint tracker and get changes
            changes = self.endpoint_tracker.update_endpoints(current_endpoints)
            
            if changes:
                self.logger.info(f"Detected {len(changes)} endpoint changes")
                self.send_status_alerts(changes)
            else:
                self.logger.info("No endpoint changes detected")
            
            # Check for stale endpoints
            self.check_stale_endpoints()
            
            # Generate periodic status report (every hour)
            current_time = datetime.utcnow()
            if current_time.minute < 5:  # First 5 minutes of each hour
                self.generate_status_report(current_endpoints)
            
            self.logger.info("Endpoint monitoring cycle completed successfully")
        
        except Exception as e:
            self.logger.error(f"Error in monitoring cycle: {e}")
    
    def run(self):
        """Main run loop"""
        self.logger.info("Starting Netskope Endpoint Monitor...")
        
        # Connect to Wazuh
        if not self.wazuh_sender.connect():
            self.logger.error("Failed to connect to Wazuh manager")
            sys.exit(1)
        
        # Main monitoring loop
        while True:
            try:
                self.run_monitoring_cycle()
                
                # Wait 5 minutes before next cycle
                time.sleep(300)
                
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal, stopping...")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
        
        # Cleanup
        self.wazuh_sender.close()
        self.logger.info("Endpoint monitor stopped")

if __name__ == "__main__":
    try:
        monitor = EndpointMonitor()
        monitor.run()
    except Exception as e:
        print(f"Fatal error starting endpoint monitor: {e}")
        sys.exit(1)