import datetime
import re

from flask import (Blueprint, current_app, render_template, helpers,
    url_for, request, redirect, flash)
from werkzeug import secure_filename

from flask.ext import login

from mongokit import ValidationError

from victims_hash.fingerprint import fingerprint
from victims_hash.metadata import extract_metadata
#from victims_web import errors


ui = Blueprint('ui', __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static/')  # Last argument needed since we register on /


def _is_hash(data):
    """
    Verifies the hash is a sha1 hash.
    """
    if re.match('^([a-zA-Z0-9]{128})$', data):
        return True
    return False


@ui.route('/', methods=['GET'])
def index():
    kwargs = {
        'hashes': current_app.db.Hash.find().count(),
        'pending': current_app.db.Hash.find({'status': 'Pending'}).count(),
        'jars': current_app.db.Hash.find(
            {'format': 'Jar'}).count(),
        'pending_jars': current_app.db.Hash.find({'format': 'Jar', 'status': 'PENDING'}).count(),
        'eggs': current_app.db.Hash.find(
            {'format': 'Egg'}).count(),
        'pending_eggs': current_app.db.Hash.find({'format': 'Egg', 'status': 'PENDING'}).count(),
    }
    return render_template('index.html',  **kwargs)


@ui.route('/hashes/', methods=['GET'])
@ui.route('/hashes/<format>/', methods=['GET'])
def hashes(format=None):
    filters = {
        'status': 'RELEASED',
    }
    if format:
        formats = current_app.db.Hash.find(
            fields={'format': '1'}).distinct('format')

        if format in formats:
            filters['format'] = format
        if format not in formats:
            flash('Format not found', 'error')

    hashes = current_app.db.Hash.find(filters)
    return render_template('hashes.html', hashes=hashes)


@ui.route('/hash/<hash>/', methods=['GET'])
def hash(hash):
    if _is_hash(hash):
        a_hash = current_app.db.Hash.find_one_or_404({'hashes.sha512.combined': hash})
        return render_template('onehash.html', hash=a_hash)
    flash('Not a valid hash', 'error')
    return redirect(url_for('ui.hashes'))


@ui.route('/submit_archive/', methods=['GET', 'POST'])
@login.login_required
def submit_archive():
    # If a file is submitted
    if request.method == "POST":
       archive = request.files['archive']
       # TODO: vvvvvvvvvvvvvvvvvvvvvvvvv
       #if archive and allowed_file(archive.filename):
       filename = secure_filename(archive.filename)
       try:
           if current_app.db.Hash.find({
                        'name': filename,
                        'version': '1.0.0',
                    }).count() > 0:
               raise ValidationError('The hash already exists.')

           hashes = fingerprint(filename, io=archive.stream)['hashes']
           cves = request.form['cves'].split(',')

           new_hash = current_app.db.Hash()
           new_hash.name = filename
           new_hash.date = datetime.datetime.utcnow()
           new_hash.version = '1.0.0'
           new_hash.format = filename[filename.rfind('.') + 1:].capitalize()
           new_hash.cves = cves
           new_hash.status = 'SUBMITTED'
           new_hash.submitter = login.current_user.username
           new_hash.hashes = hashes
           # Reset the location in the stream
           archive.stream.seek(0)
           new_hash.meta = extract_metadata(filename, io=archive.stream)['meta']
           new_hash.validate()
           new_hash.save()

           flash('Archive Submitted.', 'info')
       except ValidationError, ve:
            flash(ve.message, 'error')

    return render_template('submit_archive.html')


@ui.route('/<page>.html', methods=['GET'])
def static_page(page):
    # These are the only 'static' pages
    if page in ['about', 'client', 'bugs']:
        return render_template('%s.html' % page)
    return helpers.NotFound()
