from flask import Blueprint, render_template, redirect, url_for
from state import active_attacks, stats, attack_history

pages_bp = Blueprint('pages', __name__)

@pages_bp.route('/')
def dashboard():
    active_count = sum(1 for v in active_attacks.values() if v)
    return render_template('index.html',
                           stats=stats, history=attack_history[:15],
                           active_count=active_count)

