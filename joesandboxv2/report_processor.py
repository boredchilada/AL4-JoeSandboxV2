#!/usr/bin/env python3

from typing import Dict, Any

from assemblyline_v4_service.common.result import Result, ResultSection
from assemblyline_service_utilities.common.dynamic_service_helper import attach_dynamic_ontology

from joesandboxv2.processors.ontology_processor import OntologyProcessor
from joesandboxv2.processors.signature_processor import SignatureProcessor
from joesandboxv2.processors.network_processor import NetworkProcessor
from joesandboxv2.processors.file_processor import FileProcessor


class ReportProcessor:
    """Coordinator for processing Joe Sandbox analysis reports"""
    
    def __init__(self, service_name: str, logger):
        """
        Initialize the report processor
        
        Args:
            service_name: The name of the service
            logger: Logger instance for logging
        """
        self.service_name = service_name
        self.log = logger
        
        # Initialize sub-processors
        self.ontology_processor = OntologyProcessor(service_name, logger)
        self.signature_processor = SignatureProcessor(service_name, logger)
        self.network_processor = NetworkProcessor(service_name, logger)
        self.file_processor = FileProcessor(service_name, logger)
    
    def process_report(self, report: Dict[str, Any], result: Result, request, service) -> None:
        """
        Process the irjsonfixed report and add results to the Result object
        
        Args:
            report: The Joe Sandbox report data
            result: The Result object to add sections to
            request: The ServiceRequest object
            service: The service instance
        """
        try:
            # Extract analysis data
            analysis = report.get('analysis', {})
            
            # Create main section with summary
            main_section = ResultSection("Joe Sandbox Analysis Results")
            
            # Add basic information
            self._add_basic_info(analysis, main_section)
            
            # Create ontology results
            ontology = self.ontology_processor.create_ontology(analysis)
            
            # Process signatures
            signatures = analysis.get('signatures', {}).get('signare', [])
            if signatures:
                self.signature_processor.process_signatures(signatures, ontology, main_section)
            
            # Process network indicators
            contacted = analysis.get('contacted', {})
            self.network_processor.process_network_data(contacted, ontology, main_section)
            
            # Process dropped files
            self.file_processor.process_dropped_files(analysis, main_section)
            
            # Add the main section to the result
            result.add_section(main_section)
            
            # Add process tree section if available
            if ontology.processes:
                process_tree_section = ontology.get_process_tree_result_section()
                if process_tree_section:
                    result.add_section(process_tree_section)
            
            # Attach ontology to the service
            attach_dynamic_ontology(service, ontology)
            
        except Exception as e:
            self.log.error(f"Error processing report: {str(e)}")
            error_section = ResultSection("Report Processing Error")
            error_section.add_line(f"An error occurred while processing the report: {str(e)}")
            result.add_section(error_section)
    
    def _add_basic_info(self, analysis: Dict[str, Any], main_section: ResultSection) -> None:
        """
        Add basic information to the result section
        
        Args:
            analysis: The Joe Sandbox analysis data
            main_section: The result section to add information to
        """
        # Add basic information
        main_section.add_line(f"Analysis ID: {analysis.get('id')}")
        main_section.add_line(f"Sample: {analysis.get('sample')}")
        main_section.add_line(f"Analysis Date: {analysis.get('startdate')} {analysis.get('starttime')}")
        main_section.add_line(f"System: {analysis.get('system')}")
        
        # Add detection information
        detection = analysis.get('detection', {})
        score = detection.get('score', 0)
        
        # Set heuristic based on detection
        if detection.get('malicious', False):
            main_section.set_heuristic(1)  # Malicious
            main_section.add_line("Verdict: Malicious")
        elif detection.get('suspicious', False):
            main_section.set_heuristic(2)  # Suspicious
            main_section.add_line("Verdict: Suspicious")
        else:
            main_section.set_heuristic(3)  # Clean/Unknown
            main_section.add_line("Verdict: Clean/Unknown")
        
        main_section.add_line(f"Score: {score}/100")
        
        # Add confidence information
        confidence = analysis.get('confidence', {})
        main_section.add_line(f"Confidence Score: {confidence.get('score', 0)}/{confidence.get('maxscore', 5)}")