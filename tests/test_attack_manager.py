# tests/test_attack_manager.py
import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.attack_manager import AttackManager

class TestAttackManager(unittest.TestCase):
    def setUp(self):
        self.attack_mgr = AttackManager()
    
    def test_load_techniques(self):
        techniques = self.attack_mgr.load_techniques()
        self.assertGreater(len(techniques), 0)
    
    def test_get_technique_by_id(self):
        technique = self.attack_mgr.get_technique_by_id('T1055')
        self.assertIsNotNone(technique)
        self.assertEqual(technique['technique_id'], 'T1055')
    
    def test_search_techniques(self):
        results = self.attack_mgr.search_techniques('injection')
        self.assertGreater(len(results), 0)

if __name__ == '__main__':
    unittest.main()