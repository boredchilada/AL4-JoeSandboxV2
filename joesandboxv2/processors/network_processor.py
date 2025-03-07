#!/usr/bin/env python3

from typing import Dict, List, Optional, Any

from assemblyline_v4_service.common.result import ResultSection
from assemblyline_service_utilities.common.dynamic_service_helper import (
    OntologyResults, 
    ObjectID, 
    NetworkConnection, 
    NetworkDNS, 
    NetworkHTTP
)


class NetworkProcessor:
    """Processor for Joe Sandbox network data"""
    
    def __init__(self, service_name: str, logger):
        """
        Initialize the network processor
        
        Args:
            service_name: The name of the service
            logger: Logger instance for logging
        """
        self.service_name = service_name
        self.log = logger
    
    def process_network_data(self, contacted: Dict[str, Any], ontology: OntologyResults, result_section: ResultSection) -> None:
        """
        Process Joe Sandbox network data and add it to ontology and result section
        
        Args:
            contacted: The contacted data from Joe Sandbox
            ontology: The ontology results to add network data to
            result_section: The result section to add tags to
        """
        # Process domains
        self._process_domains(contacted, ontology, result_section)
        
        # Process IPs
        self._process_ips(contacted, ontology, result_section)
        
        # Process URLs
        self._process_urls(contacted, ontology, result_section)
    
    def _process_domains(self, contacted: Dict[str, Any], ontology: OntologyResults, result_section: ResultSection) -> None:
        """
        Process domain data
        
        Args:
            contacted: The contacted data from Joe Sandbox
            ontology: The ontology results to add domain data to
            result_section: The result section to add tags to
        """
        # Process domains - Handle null values
        domains_obj = contacted.get('domains')
        domains = []
        if domains_obj is not None:  # Check if domains is not None
            domains = domains_obj.get('domain', [])
        
        if domains:
            domain_text = "Contacted Domains:\n"
            for domain in domains:
                domain_name = domain.get('name', '')
                is_malicious = domain.get('malicious', False)
                ip = domain.get('ip', '')
                
                if domain_name:
                    domain_text += f"- {domain_name} {'(Malicious)' if is_malicious else ''}\n"
                    # Add tag directly to main section
                    result_section.add_tag('network.static.domain', domain_name)
                    
                    # Add to ontology
                    self._add_network_dns(ontology, domain_name, [ip] if ip else [])
            
            result_section.add_line(domain_text)
    
    def _process_ips(self, contacted: Dict[str, Any], ontology: OntologyResults, result_section: ResultSection) -> None:
        """
        Process IP data
        
        Args:
            contacted: The contacted data from Joe Sandbox
            ontology: The ontology results to add IP data to
            result_section: The result section to add tags to
        """
        # Process IPs
        ips_obj = contacted.get('ips')
        ips = []
        if ips_obj is not None:  # Check if ips is not None
            ips = ips_obj.get('ip', [])
        
        if ips:
            ip_text = "Contacted IP Addresses:\n"
            for ip in ips:
                ip_value = ip.get('$', '')
                is_malicious = ip.get('@malicious', 'false').lower() == 'true'
                
                if ip_value:
                    ip_text += f"- {ip_value} {'(Malicious)' if is_malicious else ''}\n"
                    # Add tag directly to main section
                    result_section.add_tag('network.static.ip', ip_value)
                    
                    # Add to ontology
                    self._add_network_connection(ontology, ip_value, None, is_malicious)
            
            result_section.add_line(ip_text)
    
    def _process_urls(self, contacted: Dict[str, Any], ontology: OntologyResults, result_section: ResultSection) -> None:
        """
        Process URL data
        
        Args:
            contacted: The contacted data from Joe Sandbox
            ontology: The ontology results to add URL data to
            result_section: The result section to add tags to
        """
        # Process URLs
        urls_obj = contacted.get('urls')
        urls = []
        if urls_obj is not None:  # Check if urls is not None
            urls = urls_obj.get('url', [])
        
        if urls:
            url_text = "Contacted URLs:\n"
            for url in urls:
                url_name = url.get('name', '')
                is_malicious = url.get('malicious', False)
                ip = url.get('ip', '')
                
                if url_name:
                    url_text += f"- {url_name} {'(Malicious)' if is_malicious else ''}\n"
                    # Add tag directly to main section
                    result_section.add_tag('network.static.uri', url_name)
                    
                    # Add to ontology
                    self._add_network_http(ontology, url_name, ip)
            
            result_section.add_line(url_text)
    
    def _add_network_connection(self, ontology: OntologyResults, ip: str, port: Optional[int] = None, is_malicious: bool = False) -> None:
        """
        Add a network connection to ontology
        
        Args:
            ontology: The ontology results to add the connection to
            ip: The destination IP address
            port: The destination port (optional)
            is_malicious: Whether the connection is malicious
        """
        if not ip:
            return
        
        # Create a unique ID for the connection
        conn_id = f"conn_{hash(ip + str(port or 0)) & 0xffffffff}"
        
        # Create ObjectID for the connection
        objectid = ObjectID(
            tag=f"{ip}:{port or 0}",
            ontology_id=conn_id,
            service_name=self.service_name
        )
        
        # Create the network connection
        network_connection = NetworkConnection(
            objectid=objectid,
            destination_ip=ip,
            destination_port=port or 0,  # Default to 0 if port is not provided
            transport_layer_protocol="tcp",  # Default to TCP
            direction="outbound"  # Default to outbound
        )
        
        # Add the network connection to ontology
        ontology.add_network_connection(network_connection)
    
    def _add_network_dns(self, ontology: OntologyResults, domain: str, resolved_ips: List[str]) -> None:
        """
        Add a DNS record to ontology
        
        Args:
            ontology: The ontology results to add the DNS record to
            domain: The domain name
            resolved_ips: List of resolved IP addresses
        """
        if not domain:
            return
        
        # Create a DNS record
        dns = NetworkDNS(
            domain=domain,
            resolved_ips=resolved_ips or ["0.0.0.0"],  # Default to 0.0.0.0 if no IPs
            lookup_type="A"  # Default to A record
        )
        
        # Add the DNS record to ontology
        ontology.add_network_dns(dns)
        
        # For each resolved IP, create a network connection with DNS details
        for ip in resolved_ips:
            if ip and ip != "unknown":
                # Create a unique ID for the connection
                conn_id = f"conn_dns_{hash(domain + ip) & 0xffffffff}"
                
                # Create ObjectID for the connection
                objectid = ObjectID(
                    tag=f"{domain}:{53}",  # DNS uses port 53
                    ontology_id=conn_id,
                    service_name=self.service_name
                )
                
                # Create the network connection
                network_connection = NetworkConnection(
                    objectid=objectid,
                    destination_ip=ip,
                    destination_port=53,  # DNS uses port 53
                    transport_layer_protocol="udp",  # DNS typically uses UDP
                    direction="outbound",
                    dns_details=dns,
                    connection_type="dns"
                )
                
                # Add the network connection to ontology
                ontology.add_network_connection(network_connection)
    
    def _add_network_http(self, ontology: OntologyResults, url: str, ip: Optional[str] = None) -> None:
        """
        Add an HTTP request to ontology
        
        Args:
            ontology: The ontology results to add the HTTP request to
            url: The URL
            ip: The destination IP address (optional)
        """
        if not url:
            return
        
        # Create HTTP details
        http = NetworkHTTP(
            request_uri=url,
            request_method="GET"  # Default to GET
        )
        
        # Add the HTTP record to ontology
        ontology.add_network_http(http)
        
        # If IP is provided, create a network connection with HTTP details
        if ip and ip != "unknown":
            # Create a unique ID for the connection
            conn_id = f"conn_http_{hash(url + ip) & 0xffffffff}"
            
            # Create ObjectID for the connection
            objectid = ObjectID(
                tag=f"{ip}:{80}",  # HTTP uses port 80
                ontology_id=conn_id,
                service_name=self.service_name
            )
            
            # Create the network connection
            network_connection = NetworkConnection(
                objectid=objectid,
                destination_ip=ip,
                destination_port=80,  # HTTP uses port 80
                transport_layer_protocol="tcp",  # HTTP uses TCP
                direction="outbound",
                http_details=http,
                connection_type="http"
            )
            
            # Add the network connection to ontology
            ontology.add_network_connection(network_connection)