from flask import Blueprint, request, jsonify
from modules import network_discovery

network_bp = Blueprint('network', __name__)

@network_bp.route('/api/network/discover', methods=['POST', 'GET', 'DELETE'])
def api_network_discover():
    if request.method == 'POST':
        data = request.json
        subnet = data.get('subnet', '192.168.1.0/24')
        res = network_discovery.discovery_module.scan(subnet)
        return jsonify(res)
    elif request.method == 'DELETE':
        res = network_discovery.discovery_module.stop()
        return jsonify(res)
    else:
        return jsonify(network_discovery.discovery_module.get_results())
