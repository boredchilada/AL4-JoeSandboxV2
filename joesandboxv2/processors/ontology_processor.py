#!/usr/bin/env python3

import uuid
from typing import Dict, Any

from assemblyline.common.isotime import now_as_iso
from assemblyline_service_utilities.common.dynamic_service_helper import (
    OntologyResults, 
    Sandbox, 
    ObjectID
)


class OntologyProcessor:
    """Processor for creating and managing ontology"""
    
    def __init__(self, service_name: str, logger):
        """
        Initialize the ontology processor
        
        Args:
            service_name: The name of the service
            logger: Logger instance for logging
        """
        self.service_name = service_name
        self.log = logger
    
    def create_ontology(self, analysis: Dict[str, Any]) -> OntologyResults:
        """
        Create ontology results from Joe Sandbox analysis data
        
        Args:
            analysis: The Joe Sandbox analysis data
            
        Returns:
            OntologyResults: The created ontology results
        """
        ontology = OntologyResults(self.service_name)
        
        # Create a session ID
        session_id = str(uuid.uuid4())
        
        # Create sandbox object
        sandbox_objectid = ObjectID(
            tag=f"joe_sandbox_{analysis.get('id', '')}",
            ontology_id=f"joe_sandbox_{analysis.get('id', '')}",
            service_name=self.service_name,
            session=session_id
        )
        
        # Parse start date and time
        start_date = analysis.get('startdate', '')
        start_time = analysis.get('starttime', '')
        start_datetime = None
        
        try:
            # Try to parse the date and time
            if start_date and start_time:
                # Convert from DD/MM/YYYY format to YYYY-MM-DD
                if '/' in start_date:
                    day, month, year = start_date.split('/')
                    start_date = f"{year}-{month}-{day}"
                
                start_datetime = f"{start_date}T{start_time}"
        except Exception as e:
            self.log.warning(f"Error parsing date/time: {str(e)}")
            start_datetime = now_as_iso()
        
        # Create sandbox analysis metadata
        sandbox_analysis_metadata = Sandbox.AnalysisMetadata()
        sandbox_analysis_metadata.start_time = start_datetime or now_as_iso()
        sandbox_analysis_metadata.task_id = analysis.get('id')
        
        # Create machine metadata
        machine_metadata = Sandbox.AnalysisMetadata.MachineMetadata()
        
        # Normalize platform value to match expected format
        platform_value = analysis.get('arch', '')
        if platform_value and isinstance(platform_value, str):
            # Convert to proper case for validation
            if platform_value.upper() == 'WINDOWS':
                platform_value = 'Windows'
            elif platform_value.upper() == 'LINUX':
                platform_value = 'Linux'
            elif platform_value.upper() == 'MACOS':
                platform_value = 'MacOS'
            elif platform_value.upper() == 'ANDROID':
                platform_value = 'Android'
            elif platform_value.upper() == 'IOS':
                platform_value = 'iOS'
        
        machine_metadata.platform = platform_value
        machine_metadata.version = analysis.get('system', '')
        
        sandbox_analysis_metadata.machine_metadata = machine_metadata
        
        # Create sandbox object
        sandbox = Sandbox(
            objectid=sandbox_objectid,
            analysis_metadata=sandbox_analysis_metadata,
            sandbox_name="Joe Sandbox",
            sandbox_version=analysis.get('version', '')
        )
        
        # Add sandbox to ontology
        ontology.add_sandbox(sandbox)
        
        return ontology