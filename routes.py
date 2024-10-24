import os
from flask import render_template, request, redirect, url_for, flash, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app import app, db
from models import User, SignedApp
from signing import IPASigner

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        new_user = User()
        new_user.username = request.form['username']
        new_user.password_hash = generate_password_hash(request.form['password'])
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    apps = SignedApp.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', apps=apps)

@app.route('/sign', methods=['POST'])
@login_required
def sign_app():
    if 'ipa' not in request.files or 'p12' not in request.files or 'provision' not in request.files:
        flash('Missing required files')
        return redirect(url_for('dashboard'))

    ipa_file = request.files['ipa']
    p12_file = request.files['p12']
    provision_file = request.files['provision']
    p12_password = request.form['p12_password']

    # Save files
    upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    os.makedirs(upload_dir, exist_ok=True)

    if not ipa_file.filename or not p12_file.filename or not provision_file.filename:
        flash('Invalid file names')
        return redirect(url_for('dashboard'))

    ipa_path = os.path.join(upload_dir, secure_filename(ipa_file.filename))
    p12_path = os.path.join(upload_dir, secure_filename(p12_file.filename))
    provision_path = os.path.join(upload_dir, secure_filename(provision_file.filename))

    ipa_file.save(ipa_path)
    p12_file.save(p12_path)
    provision_file.save(provision_path)

    # Sign IPA
    signer = IPASigner(ipa_path, p12_path, provision_path, p12_password)
    success, signed_path = signer.sign_ipa()

    if success:
        # Create manifest and save app
        app_url = request.host_url + 'download/' + os.path.basename(signed_path)
        bundle_id = signer.extract_bundle_id()
        manifest = IPASigner.generate_manifest(bundle_id, app_url, 'Signed App')
        
        manifest_path = os.path.join(upload_dir, 'manifest_' + os.path.basename(signed_path) + '.plist')
        with open(manifest_path, 'wb') as f:
            f.write(manifest)

        signed_app = SignedApp()
        signed_app.user_id = current_user.id
        signed_app.app_name = os.path.basename(ipa_path)
        signed_app.bundle_id = bundle_id
        signed_app.ipa_path = signed_path
        signed_app.plist_path = manifest_path
        signed_app.installation_url = f"itms-services://?action=download-manifest&url={request.host_url}manifest/{os.path.basename(manifest_path)}"
        
        db.session.add(signed_app)
        db.session.commit()
        
        flash('App signed successfully')
    else:
        flash('Error signing app: ' + signed_path)

    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/manifest/<filename>')
def serve_manifest(filename):
    return send_file(
        os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename),
        mimetype='application/x-plist'
    )

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(
        os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename),
        mimetype='application/octet-stream',
        as_attachment=True
    )
