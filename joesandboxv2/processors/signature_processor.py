#!/usr/bin/env python3

from typing import List

from assemblyline_v4_service.common.result import ResultSection
from assemblyline_service_utilities.common.dynamic_service_helper import (
    OntologyResults, 
    ObjectID, 
    Signature
)


class SignatureProcessor:
    """Processor for Joe Sandbox signatures"""
    
    def __init__(self, service_name: str, logger):
        """
        Initialize the signature processor
        
        Args:
            service_name: The name of the service
            logger: Logger instance for logging
        """
        self.service_name = service_name
        self.log = logger
    
    def process_signatures(self, signatures: List[str], ontology: OntologyResults, result_section: ResultSection) -> None:
        """
        Process Joe Sandbox signatures and add them to ontology and result section
        
        Args:
            signatures: List of signature names
            ontology: The ontology results to add signatures to
            result_section: The result section to add tags to
        """
        if not signatures:
            return
        
        sig_text = "Detected Behaviors:\n"
        
        for signature_name in signatures:
            # Add to result text
            sig_text += f"- {signature_name}\n"
            
            # Add each signature as a tag using the appropriate tag types from the tagging model
            result_section.add_tag('dynamic.signature.name', signature_name)
            result_section.add_tag('file.behavior', signature_name)
            
            # Categorize signatures into appropriate technique tags if possible
            self._categorize_signature(signature_name, result_section)
            
            # Add to ontology
            self._add_signature_to_ontology(signature_name, ontology)
        
        # Add the signature text to the result section
        result_section.add_line(sig_text)
    
    def _categorize_signature(self, signature: str, result_section: ResultSection) -> None:
        """
        Categorize a signature into appropriate technique tags
        
        Args:
            signature: The signature name
            result_section: The result section to add tags to
        """
        signature_lower = signature.lower()
        
        if any(keyword in signature_lower for keyword in ['communication', 'connect', 'c2', 'command', 'control']):
            result_section.add_tag('technique.comms_routine', signature)
        elif any(keyword in signature_lower for keyword in ['persistence', 'autorun', 'startup', 'registry']):
            result_section.add_tag('technique.persistence', signature)
        elif any(keyword in signature_lower for keyword in ['obfuscation', 'obfuscated', 'hidden']):
            result_section.add_tag('technique.obfuscation', signature)
        elif any(keyword in signature_lower for keyword in ['crypto', 'encrypt', 'decrypt']):
            result_section.add_tag('technique.crypto', signature)
        elif any(keyword in signature_lower for keyword in ['keylog', 'keyboard']):
            result_section.add_tag('technique.keylogger', signature)
        elif any(keyword in signature_lower for keyword in ['shellcode', 'shell']):
            result_section.add_tag('technique.shellcode', signature)
        elif any(keyword in signature_lower for keyword in ['packer', 'packed']):
            result_section.add_tag('technique.packer', signature)
        elif any(keyword in signature_lower for keyword in ['macro']):
            result_section.add_tag('technique.macro', signature)
        elif any(keyword in signature_lower for keyword in ['config', 'configuration']):
            result_section.add_tag('technique.config', signature)
    
    def _add_signature_to_ontology(self, signature_name: str, ontology: OntologyResults) -> None:
        """
        Add a signature to ontology
        
        Args:
            signature_name: The signature name
            ontology: The ontology results to add the signature to
        """
        # Create a unique ID for the signature
        sig_id = f"sig_{hash(signature_name) & 0xffffffff}"
        
        # Create ObjectID for the signature
        objectid = ObjectID(
            tag=signature_name,
            ontology_id=sig_id,
            service_name=self.service_name
        )
        
        # Create the signature
        signature = Signature(
            objectid=objectid,
            name=signature_name,
            type="CUCKOO",  # Using CUCKOO as the type since Joe Sandbox is similar
            classification="DETECTION"
        )
        
        # Add the signature to ontology
        ontology.add_signature(signature)