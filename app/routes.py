# app/routes.py
from flask import Blueprint, render_template, request, jsonify
import logging
from app.modules.attack_manager import AttackManager
from app.modules.alert_enricher import AlertEnricher

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

main = Blueprint('main', __name__)

# Initialize managers with error handling
try:
    attack_mgr = AttackManager()
    alert_enricher = AlertEnricher()
    logger.info("Managers initialized successfully")
except Exception as e:
    logger.error(f"Error initializing managers: {e}")
    # Create fallback instances
    attack_mgr = None
    alert_enricher = None

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/dashboard')
def dashboard():
    try:
        if not attack_mgr:
            return render_template('error.html', error="Attack manager not initialized")
        
        tactics = attack_mgr.get_tactics()
        techniques = attack_mgr.load_techniques()
        
        stats = {
            'total_techniques': len(techniques),
            'total_tactics': len(tactics),
            'subtechniques': len([t for t in techniques if t.get('is_subtechnique', False)])
        }
        
        return render_template('dashboard.html', 
                             tactics=tactics, 
                             stats=stats,
                             techniques=techniques[:10])  # Show first 10
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('error.html', error=str(e))

@main.route('/techniques')
def techniques():
    try:
        if not attack_mgr:
            return render_template('error.html', error="Attack manager not initialized")
        
        tactic = request.args.get('tactic', '')
        
        if tactic:
            techniques = attack_mgr.get_techniques_by_tactic(tactic)
        else:
            techniques = attack_mgr.load_techniques()
        
        return render_template('techniques.html', techniques=techniques)
    
    except Exception as e:
        logger.error(f"Techniques error: {e}")
        return render_template('error.html', error=str(e))

@main.route('/technique/<technique_id>')
def technique_detail(technique_id):
    try:
        if not attack_mgr:
            return render_template('error.html', error="Attack manager not initialized")
        
        technique = attack_mgr.get_technique_by_id(technique_id)
        mitigations = []
        
        if technique:
            mitigations = attack_mgr.get_technique_mitigations(technique_id)
        
        return render_template('technique_detail.html', 
                             technique=technique, 
                             mitigations=mitigations)
    
    except Exception as e:
        logger.error(f"Technique detail error: {e}")
        return render_template('error.html', error=str(e))

@main.route('/alert-enrichment', methods=['GET', 'POST'])
def alert_enrichment():
    if request.method == 'POST':
        try:
            if not alert_enricher:
                return jsonify({'error': 'Alert enricher not available'}), 500
            
            alert_data = request.get_json()
            enriched_alert = alert_enricher.enrich_alert(alert_data)
            return jsonify(enriched_alert)
        except Exception as e:
            logger.error(f"Alert enrichment error: {e}")
            return jsonify({'error': str(e)}), 500
    
    return render_template('alert_enrichment.html')

@main.route('/threat-hunting')
def threat_hunting():
    try:
        if not attack_mgr:
            return render_template('error.html', error="Attack manager not initialized")
        
        tactics = attack_mgr.get_tactics()
        return render_template('threat_hunting.html', tactics=tactics)
    
    except Exception as e:
        logger.error(f"Threat hunting error: {e}")
        return render_template('error.html', error=str(e))

@main.route('/api/search')
def api_search():
    try:
        if not attack_mgr:
            return jsonify({'error': 'Service unavailable'}), 503
        
        query = request.args.get('q', '')
        if query:
            results = attack_mgr.search_techniques(query)
            return jsonify(results)
        return jsonify([])
    
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({'error': str(e)}), 500

@main.route('/api/enrich-alert', methods=['POST'])
def api_enrich_alert():
    try:
        if not alert_enricher:
            return jsonify({'error': 'Alert enricher not available'}), 503
        
        alert_data = request.get_json()
        enriched_alert = alert_enricher.enrich_alert(alert_data)
        return jsonify(enriched_alert)
    
    except Exception as e:
        logger.error(f"API enrich alert error: {e}")
        return jsonify({'error': str(e)}), 500

@main.route('/health')
def health():
    """Health check endpoint"""
    status = {
        'attack_manager': bool(attack_mgr),
        'alert_enricher': bool(alert_enricher),
        'status': 'healthy' if (attack_mgr and alert_enricher) else 'degraded'
    }
    return jsonify(status)