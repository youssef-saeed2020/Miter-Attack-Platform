# app/modules/attack_manager.py
import json
import logging
import pandas as pd
from typing import Dict, List, Optional
import os

class AttackManager:
    def __init__(self):
        self.techniques_cache = None
        self.tactics_cache = None
        self.logger = logging.getLogger(__name__)
        self.data_file = 'app/data/mitre_techniques.json'
        
    def load_techniques(self, force_refresh=False) -> List[Dict]:
        """Load techniques with multiple fallback methods"""
        if self.techniques_cache is None or force_refresh:
            self.techniques_cache = self._load_from_cache()
            
            if not self.techniques_cache:
                self.techniques_cache = self._load_from_backup_data()
                
            if not self.techniques_cache:
                self.techniques_cache = self._load_sample_techniques()
                
        return self.techniques_cache
    
    def _load_from_cache(self) -> List[Dict]:
        """Try to load from local cache file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.logger.info(f"Loaded {len(data)} techniques from cache")
                    return data
        except Exception as e:
            self.logger.warning(f"Failed to load from cache: {e}")
        return []
    
    def _load_from_backup_data(self) -> List[Dict]:
        """Try to load from embedded backup data"""
        try:
            # Try to use attackcti if available
            from attackcti import attack_client
            self.logger.info("Attempting to load from MITRE ATT&CK API...")
            
            lift = attack_client()
            techniques = lift.get_techniques()
            
            technique_list = []
            for tech in techniques:
                technique_data = self._parse_technique(tech)
                if technique_data:
                    technique_list.append(technique_data)
            
            # Cache the data for future use
            self._save_to_cache(technique_list)
            return technique_list
            
        except Exception as e:
            self.logger.warning(f"Failed to load from MITRE API: {e}")
            return []
    
    def _load_sample_techniques(self) -> List[Dict]:
        """Load sample techniques as final fallback"""
        self.logger.info("Loading sample techniques...")
        return [
            {
                'id': 'attack-pattern-1',
                'technique_id': 'T1055',
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes to evade process-based defenses.',
                'tactics': ['Defense Evasion', 'Privilege Escalation'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'url': 'https://attack.mitre.org/techniques/T1055',
                'data_sources': ['Process monitoring', 'API monitoring'],
                'is_subtechnique': False
            },
            {
                'id': 'attack-pattern-2',
                'technique_id': 'T1566.001',
                'name': 'Phishing: Spearphishing Attachment',
                'description': 'Adversaries may send spearphishing emails with a malicious attachment.',
                'tactics': ['Initial Access'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'url': 'https://attack.mitre.org/techniques/T1566/001',
                'data_sources': ['Network traffic', 'Email gateway'],
                'is_subtechnique': True
            },
            {
                'id': 'attack-pattern-3',
                'technique_id': 'T1027',
                'name': 'Obfuscated Files or Information',
                'description': 'Adversaries may attempt to make an executable or file difficult to discover.',
                'tactics': ['Defense Evasion'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'url': 'https://attack.mitre.org/techniques/T1027',
                'data_sources': ['File monitoring', 'Process monitoring'],
                'is_subtechnique': False
            },
            {
                'id': 'attack-pattern-4',
                'technique_id': 'T1082',
                'name': 'System Information Discovery',
                'description': 'Adversaries may attempt to get detailed information about the operating system and hardware.',
                'tactics': ['Discovery'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'url': 'https://attack.mitre.org/techniques/T1082',
                'data_sources': ['Process command-line parameters', 'Process monitoring'],
                'is_subtechnique': False
            },
            {
                'id': 'attack-pattern-5',
                'technique_id': 'T1003',
                'name': 'OS Credential Dumping',
                'description': 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
                'tactics': ['Credential Access'],
                'platforms': ['Windows', 'Linux', 'macOS'],
                'url': 'https://attack.mitre.org/techniques/T1003',
                'data_sources': ['Process monitoring', 'API monitoring'],
                'is_subtechnique': False
            }
        ]
    
    def _parse_technique(self, tech) -> Optional[Dict]:
        """Parse a technique object into a dictionary"""
        try:
            external_id = None
            url = None
            
            if hasattr(tech, 'external_references') and tech.external_references:
                for ref in tech.external_references:
                    if hasattr(ref, 'external_id') and ref.external_id:
                        external_id = ref.external_id
                    if hasattr(ref, 'url') and ref.url:
                        url = ref.url
            
            tactics = []
            if hasattr(tech, 'kill_chain_phases') and tech.kill_chain_phases:
                for phase in tech.kill_chain_phases:
                    if hasattr(phase, 'phase_name'):
                        tactics.append(phase.phase_name)
            
            return {
                'id': getattr(tech, 'id', ''),
                'technique_id': external_id,
                'name': getattr(tech, 'name', 'Unknown'),
                'description': getattr(tech, 'description', ''),
                'tactics': tactics,
                'platforms': getattr(tech, 'x_mitre_platforms', []),
                'url': url,
                'data_sources': getattr(tech, 'x_mitre_data_sources', []),
                'is_subtechnique': '.' in external_id if external_id else False
            }
        except Exception as e:
            self.logger.error(f"Error parsing technique: {e}")
            return None
    
    def _save_to_cache(self, techniques: List[Dict]):
        """Save techniques to local cache file"""
        try:
            os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(techniques, f, indent=2)
            self.logger.info(f"Cached {len(techniques)} techniques to {self.data_file}")
        except Exception as e:
            self.logger.error(f"Failed to cache techniques: {e}")
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get specific technique by ID"""
        techniques = self.load_techniques()
        for tech in techniques:
            if tech['technique_id'] == technique_id:
                return tech
        return None
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """Get all techniques for a specific tactic"""
        techniques = self.load_techniques()
        return [tech for tech in techniques if tactic in tech['tactics']]
    
    def search_techniques(self, query: str) -> List[Dict]:
        """Search techniques by name or description"""
        techniques = self.load_techniques()
        query = query.lower()
        
        results = []
        for tech in techniques:
            if (query in tech['name'].lower() or 
                query in tech['description'].lower() or
                (tech['technique_id'] and query in tech['technique_id'].lower())):
                results.append(tech)
        
        return results
    
    def get_technique_mitigations(self, technique_id: str) -> List[Dict]:
        """Get mitigations for a specific technique"""
        try:
            # For now, return sample mitigations based on technique
            # In a full implementation, this would query MITRE's mitigations
            mitigations_map = {
                'T1055': [
                    {'name': 'Process Whitelisting', 'description': 'Use application whitelisting to prevent execution of unauthorized processes.'},
                    {'name': 'Anti-virus', 'description': 'Use anti-virus software to detect and prevent process injection.'}
                ],
                'T1566.001': [
                    {'name': 'User Training', 'description': 'Train users to identify and report phishing attempts.'},
                    {'name': 'Anti-spoofing', 'description': 'Use email filtering to detect and block malicious attachments.'}
                ],
                'T1027': [
                    {'name': 'Application Whitelisting', 'description': 'Prevent execution of obfuscated scripts and binaries.'},
                    {'name': 'Behavioral Analysis', 'description': 'Monitor for suspicious file and process behavior.'}
                ],
                'T1082': [
                    {'name': 'System Hardening', 'description': 'Limit access to system information utilities.'},
                    {'name': 'Monitoring', 'description': 'Monitor for suspicious system information queries.'}
                ],
                'T1003': [
                    {'name': 'Credential Guard', 'description': 'Use Windows Credential Guard to protect credentials.'},
                    {'name': 'Least Privilege', 'description': 'Implement principle of least privilege to limit credential access.'}
                ]
            }
            
            return mitigations_map.get(technique_id, [
                {'name': 'General Security Controls', 'description': 'Implement standard security controls and monitoring.'}
            ])
            
        except Exception as e:
            self.logger.error(f"Error getting mitigations for {technique_id}: {e}")
            return [{'name': 'Error loading mitigations', 'description': 'Failed to load mitigation information.'}]
    
    def get_tactics(self) -> List[str]:
        """Get all available tactics"""
        if self.tactics_cache is None:
            tactics_set = set()
            techniques = self.load_techniques()
            
            for tech in techniques:
                tactics_set.update(tech['tactics'])
            
            self.tactics_cache = sorted(list(tactics_set))
        
        return self.tactics_cache
    
    def export_to_dataframe(self) -> pd.DataFrame:
        """Export techniques to pandas DataFrame"""
        techniques = self.load_techniques()
        return pd.DataFrame(techniques)