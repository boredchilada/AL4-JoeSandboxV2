#!/usr/bin/env python3

import os
from typing import Dict

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection

from joesandboxv2.api_client import JoeSandboxAPI
from joesandboxv2.report_processor import ReportProcessor


class JoeSandboxV2(ServiceBase):
    def __init__(self, config=None):
        super(JoeSandboxV2, self).__init__(config)
        
        # Log the configuration for debugging
        self.log.info(f"Service initialization started")
        
        # Try to get API key from different sources
        # 1. Check config (this is where Assemblyline passes service variables)
        if config:
            self.log.info(f"Config keys: {list(config.keys())}")
        else:
            self.log.warning("No config received")
        
        # 2. Check environment variables
        env_api_key = os.environ.get('JBX_API_KEY')
        
        # Determine which API key to use
        if config and 'api_key' in config and config['api_key']:
            self.log.info("Using API key from config")
            self.api_key = config.get('api_key')
        elif env_api_key:
            self.log.info("Using API key from environment variable JBX_API_KEY")
            self.api_key = env_api_key
        else:
            self.log.warning("No API key found in config or environment")
            self.api_key = None
        
        # Get API URL from config
        if config and 'api_url' in config:
            self.api_url = config.get('api_url')
        else:
            self.api_url = 'https://www.joesandbox.com/api/'
        
        self.log.info(f"Using API URL: {self.api_url}")
        
        # Remove trailing slash if present
        if self.api_url.endswith('/'):
            self.api_url = self.api_url[:-1]
            
        # Initialize API client
        self.api_client = JoeSandboxAPI(self.api_key, self.api_url, self.log)
        
        # Initialize report processor
        self.report_processor = ReportProcessor(self.service_attributes.name, self.log)

    def start(self):
        """Service initialization"""
        self.log.info(f"Starting {self.service_attributes.name} service")
        
        # Verify API key is set
        if not self.api_key:
            self.log.error("API key is not set. Service cannot function properly.")
            return
        
        # Verify API connection
        try:
            online = self.api_client.check_server_online()
            if online:
                self.log.info("Successfully connected to Joe Sandbox API")
            else:
                self.log.error("Joe Sandbox API is not online")
        except Exception as e:
            self.log.error(f"Failed to connect to Joe Sandbox API: {str(e)}")

    def execute(self, request: ServiceRequest) -> None:
        """Main execution function for the service"""
        result = Result()
        
        # Get file details
        file_path = request.file_path
        file_hash = request.sha256
        
        self.log.info(f"Processing file: {os.path.basename(file_path)} (SHA256: {file_hash})")
        
        try:
            # Step 1: Check if the server is online
            if not self.api_client.check_server_online():
                error_section = ResultSection("Joe Sandbox API Error")
                error_section.add_line("Joe Sandbox API is not available")
                result.add_section(error_section)
                request.result = result
                return
            
            # Step 2: Search for analyses by hash
            search_results = self.api_client.search_by_hash(file_hash)
            
            if not search_results or len(search_results) == 0:
                not_found_section = ResultSection("No Joe Sandbox Analysis Found")
                not_found_section.add_line(f"No existing analysis found for SHA256: {file_hash}")
                result.add_section(not_found_section)
                request.result = result
                return
            
            # Step 3: Get the most recent analysis
            analysis = search_results[0]  # Assuming the first result is the most recent
            webid = analysis.get('webid')
            
            # Step 4: Get detailed analysis info
            analysis_info = self.api_client.get_analysis_info(webid)
            
            # Step 5: Download the irjsonfixed report
            report = self.api_client.download_report(webid, 'irjsonfixed')
            
            if not report:
                error_section = ResultSection("Joe Sandbox Report Error")
                error_section.add_line(f"Failed to download irjsonfixed report for WebID: {webid}")
                result.add_section(error_section)
                request.result = result
                return
            
            # Step 6: Process the report and add results
            self.report_processor.process_report(report, result, request, self)
            
        except Exception as e:
            self.log.error(f"Error processing file: {str(e)}")
            error_section = ResultSection("Processing Error")
            error_section.add_line(f"An error occurred while processing the file: {str(e)}")
            result.add_section(error_section)
        
        request.result = result