# app/modules/alert_enricher.py
import re
import json
from typing import Dict, List, Optional
from .attack_manager import AttackManager

class AlertEnricher:
    def __init__(self):
        self.attack_mgr = AttackManager()
        self.pattern_mappings = self._load_pattern_mappings()
    
    def _load_pattern_mappings(self) -> Dict[str, List[str]]:
        """Load regex patterns for common techniques"""
        return {
            'T1055': [  # Process Injection
                r'WriteProcessMemory',
                r'CreateRemoteThread',
                r'VirtualAllocEx',
                r'NtMapViewOfSection'
            ],
            'T1053': [  # Scheduled Task
                r'schtasks',
                r'CreateScheduledTask',
                r'Register-ScheduledTask'
            ],
            'T1566.001': [  # Spearphishing Attachment
                r'\.scr$', r'\.js$', r'\.vbs$', r'\.docm$'
            ],
            'T1082': [  # System Information Discovery
                r'systeminfo', r'Get-WmiObject', r'hostname'
            ],
            'T1003': [  # OS Credential Dumping
                r'mimikatz', r'lsass', r'procdump', r'sekurlsa'
            ]
        }
    
    def enrich_alert(self, alert_data: Dict) -> Dict:
        """Enrich security alert with MITRE ATT&CK context"""
        enriched_alert = alert_data.copy()
        
        # Try to detect technique from alert data
        detected_techniques = self._detect_techniques(alert_data)
        
        if detected_techniques:
            enriched_alert['mitre_techniques'] = []
            
            for tech_id in detected_techniques:
                technique_info = self.attack_mgr.get_technique_by_id(tech_id)
                if technique_info:
                    technique_data = {
                        'technique_id': tech_id,
                        'technique_name': technique_info['name'],
                        'tactics': technique_info['tactics'],
                        'description': technique_info['description'],
                        'url': technique_info['url'],
                        'mitigations': self.attack_mgr.get_technique_mitigations(tech_id),
                        'confidence': self._calculate_confidence(tech_id, alert_data)
                    }
                    enriched_alert['mitre_techniques'].append(technique_data)
        
        # Add overall risk score
        enriched_alert['risk_score'] = self._calculate_risk_score(enriched_alert)
        
        return enriched_alert
    
    def _detect_techniques(self, alert_data: Dict) -> List[str]:
        """Detect MITRE techniques from alert data"""
        detected_techniques = set()
        
        # Check command line
        command_line = alert_data.get('command_line', '')
        process_name = alert_data.get('process_name', '')
        description = alert_data.get('description', '')
        
        text_to_analyze = f"{command_line} {process_name} {description}".lower()
        
        for technique_id, patterns in self.pattern_mappings.items():
            for pattern in patterns:
                if re.search(pattern, text_to_analyze, re.IGNORECASE):
                    detected_techniques.add(technique_id)
        
        return list(detected_techniques)
    
    def _calculate_confidence(self, technique_id: str, alert_data: Dict) -> int:
        """Calculate confidence level for technique detection"""
        base_confidence = 50
        
        # Increase confidence if multiple indicators match
        indicators = self.pattern_mappings.get(technique_id, [])
        matches = 0
        
        text_to_analyze = f"{alert_data.get('command_line', '')} {alert_data.get('description', '')}".lower()
        
        for pattern in indicators:
            if re.search(pattern, text_to_analyze, re.IGNORECASE):
                matches += 1
        
        if matches >= 2:
            base_confidence += 30
        elif matches == 1:
            base_confidence += 15
        
        return min(base_confidence, 100)
    
    def _calculate_risk_score(self, enriched_alert: Dict) -> int:
        """Calculate overall risk score for the alert"""
        base_score = 0
        
        # Add points based on severity
        severity_scores = {
            'Low': 20,
            'Medium': 40,
            'High': 60,
            'Critical': 80
        }
        
        base_score += severity_scores.get(enriched_alert.get('severity', 'Low'), 20)
        
        # Add points for each detected technique
        techniques = enriched_alert.get('mitre_techniques', [])
        for tech in techniques:
            base_score += tech.get('confidence', 0) * 0.2
        
        return min(int(base_score), 100)
    
    def batch_enrich_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Enrich multiple alerts at once"""
        return [self.enrich_alert(alert) for alert in alerts]