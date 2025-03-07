#!/usr/bin/env python3

import json
import requests
from typing import Dict, List, Any, Optional


class JoeSandboxAPI:
    """Client for interacting with the Joe Sandbox API"""
    
    def __init__(self, api_key: str, api_url: str, logger):
        """
        Initialize the Joe Sandbox API client
        
        Args:
            api_key: The API key for authentication
            api_url: The base URL for the Joe Sandbox API
            logger: Logger instance for logging
        """
        self.api_key = api_key
        self.api_url = api_url
        self.log = logger
    
    def check_server_online(self) -> bool:
        """
        Check if the Joe Sandbox server is online
        
        Returns:
            bool: True if the server is online, False otherwise
        """
        try:
            self.log.debug(f"Checking if server is online at: {self.api_url}/v2/server/online")
            response = requests.post(
                f"{self.api_url}/v2/server/online",
                data={'apikey': self.api_key}
            )
            response.raise_for_status()
            result = response.json()
            
            self.log.debug(f"Server online response: {json.dumps(result)}")
            
            if 'data' in result and 'online' in result['data']:
                return result['data']['online']
            return False
        except Exception as e:
            self.log.error(f"Error checking server status: {str(e)}")
            return False
    
    def search_by_hash(self, file_hash: str) -> List[Dict[str, Any]]:
        """
        Search for analyses by file hash
        
        Args:
            file_hash: The SHA256 hash of the file to search for
            
        Returns:
            List[Dict[str, Any]]: List of analysis results
        """
        try:
            self.log.debug(f"Searching for hash: {file_hash}")
            response = requests.post(
                f"{self.api_url}/v2/analysis/search",
                data={
                    'apikey': self.api_key,
                    'sha256': file_hash
                }
            )
            response.raise_for_status()
            result = response.json()
            
            if 'data' in result:
                self.log.debug(f"Found {len(result['data'])} analyses for hash {file_hash}")
                return result['data']
            return []
        except Exception as e:
            self.log.error(f"Error searching by hash: {str(e)}")
            return []
    
    def get_analysis_info(self, webid: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about an analysis
        
        Args:
            webid: The WebID of the analysis
            
        Returns:
            Optional[Dict[str, Any]]: Analysis information or None if not found
        """
        try:
            self.log.debug(f"Getting analysis info for WebID: {webid}")
            response = requests.post(
                f"{self.api_url}/v2/analysis/info",
                data={
                    'apikey': self.api_key,
                    'webid': webid
                }
            )
            response.raise_for_status()
            result = response.json()
            
            if 'data' in result:
                return result['data']
            return None
        except Exception as e:
            self.log.error(f"Error getting analysis info: {str(e)}")
            return None
    
    def download_report(self, webid: str, report_type: str = 'irjsonfixed') -> Optional[Dict[str, Any]]:
        """
        Download a report for the specified analysis
        
        Args:
            webid: The WebID of the analysis
            report_type: The type of report to download (default: 'irjsonfixed')
            
        Returns:
            Optional[Dict[str, Any]]: The report data or None if download failed
        """
        try:
            self.log.debug(f"Downloading {report_type} report for WebID: {webid}")
            response = requests.post(
                f"{self.api_url}/v2/analysis/download",
                data={
                    'apikey': self.api_key,
                    'webid': webid,
                    'type': report_type
                }
            )
            response.raise_for_status()
            
            # Parse JSON response
            return response.json()
        except Exception as e:
            self.log.error(f"Error downloading report: {str(e)}")
            return None