#!/usr/bin/env python3

from typing import Dict, List, Any

from assemblyline_v4_service.common.result import ResultSection


class FileProcessor:
    """Processor for Joe Sandbox file data"""
    
    def __init__(self, service_name: str, logger):
        """
        Initialize the file processor
        
        Args:
            service_name: The name of the service
            logger: Logger instance for logging
        """
        self.service_name = service_name
        self.log = logger
    
    def process_dropped_files(self, analysis: Dict[str, Any], result_section: ResultSection) -> None:
        """
        Process dropped files from Joe Sandbox analysis
        
        Args:
            analysis: The Joe Sandbox analysis data
            result_section: The result section to add tags to
        """
        # Process dropped files - Handle null values
        dropped_obj = analysis.get('dropped')
        dropped_files = []
        if dropped_obj is not None:  # Check if dropped is not None
            dropped_files = dropped_obj.get('file', [])
        
        if dropped_files:
            dropped_text = "Dropped Files:\n"
            for file in dropped_files:
                file_name = file.get('name', '')
                is_malicious = file.get('malicious', False)
                
                if file_name:
                    dropped_text += f"- {file_name} {'(Malicious)' if is_malicious else ''}\n"
                    
                    # Add hashes as tags if available
                    self._add_hash_tags(file, result_section)
            
            result_section.add_line(dropped_text)
    
    def _add_hash_tags(self, file: Dict[str, Any], result_section: ResultSection) -> None:
        """
        Add hash tags to the result section
        
        Args:
            file: The file data
            result_section: The result section to add tags to
        """
        if 'md5' in file:
            result_section.add_tag('file.md5', file['md5'].lower())
        if 'sha1' in file:
            result_section.add_tag('file.sha1', file['sha1'].lower())
        if 'sha256' in file:
            result_section.add_tag('file.sha256', file['sha256'].lower())