import os
from flask import render_template, request, redirect, url_for, flash, send_file, abort, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app import app, db
from models import User, SignedApp
from signing import IPASigner
from datetime import datetime, timedelta

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
    # Delete expired files
    now = datetime.utcnow()
    for app in apps:
        if app.expiration_date < now:
            try:
                if os.path.exists(app.ipa_path):
                    os.remove(app.ipa_path)
                if os.path.exists(app.plist_path):
                    os.remove(app.plist_path)
                if app.icon_url:
                    icon_path = os.path.join(current_app.root_path, 'static/uploads', 
                                           os.path.basename(app.icon_url))
                    if os.path.exists(icon_path):
                        os.remove(icon_path)
                if app.full_size_icon_url:
                    icon_path = os.path.join(current_app.root_path, 'static/uploads', 
                                           os.path.basename(app.full_size_icon_url))
                    if os.path.exists(icon_path):
                        os.remove(icon_path)
                db.session.delete(app)
            except Exception as e:
                print(f"Error deleting expired files: {e}")
    db.session.commit()
    return render_template('dashboard.html', apps=apps, now=datetime.utcnow())

def validate_icon(icon_file, max_size, expected_size):
    """Validate icon file size and dimensions"""
    from PIL import Image
    import io
    
    if not icon_file or not icon_file.filename:
        return True, None
        
    # Check file size
    icon_file.seek(0, os.SEEK_END)
    size = icon_file.tell()
    icon_file.seek(0)
    
    if size > max_size:
        return False, f'Icon file too large (max {max_size/1024/1024}MB)'
        
    # Check dimensions
    try:
        img = Image.open(icon_file)
        if img.size != (expected_size, expected_size):
            return False, f'Icon must be {expected_size}x{expected_size} pixels'
        icon_file.seek(0)
        return True, None
    except Exception as e:
        return False, str(e)

def save_icon(icon_file, upload_dir):
    """Save icon file and return URL"""
    if not icon_file or not icon_file.filename:
        return None
        
    icon_filename = secure_filename(icon_file.filename)
    icon_path = os.path.join(upload_dir, icon_filename)
    icon_file.save(icon_path)
    return request.host_url + 'download/' + icon_filename

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

    # Validate required files
    if not ipa_file.filename or not p12_file.filename or not provision_file.filename:
        flash('Invalid file names')
        return redirect(url_for('dashboard'))

    # Create upload directory
    upload_dir = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
    os.makedirs(upload_dir, exist_ok=True)

    # Save required files
    ipa_path = os.path.join(upload_dir, secure_filename(ipa_file.filename))
    p12_path = os.path.join(upload_dir, secure_filename(p12_file.filename))
    provision_path = os.path.join(upload_dir, secure_filename(provision_file.filename))

    ipa_file.save(ipa_path)
    p12_file.save(p12_path)
    provision_file.save(provision_path)

    # Handle optional icons with validation
    icon = request.files.get('icon')
    full_size_icon = request.files.get('full_size_icon')
    
    icon_url = None
    full_size_icon_url = None
    
    if icon:
        valid, error = validate_icon(icon, 1024*1024, 57)  # 1MB max, 57x57 pixels
        if not valid and error:
            flash(str(error))
            return redirect(url_for('dashboard'))
        icon_url = save_icon(icon, upload_dir)
        
    if full_size_icon:
        valid, error = validate_icon(full_size_icon, 2*1024*1024, 512)  # 2MB max, 512x512 pixels
        if not valid and error:
            flash(str(error))
            return redirect(url_for('dashboard'))
        full_size_icon_url = save_icon(full_size_icon, upload_dir)

    # Sign IPA
    try:
        signer = IPASigner(ipa_path, p12_path, provision_path, p12_password)
        success, result = signer.sign_ipa()

        if success:
            # Create manifest and save app
            app_url = request.host_url + 'download/' + os.path.basename(result)
            bundle_id = signer.extract_bundle_id()
            manifest = IPASigner.generate_manifest(
                bundle_id,
                app_url,
                'Signed App',
                icon_url,
                full_size_icon_url
            )
            
            manifest_path = os.path.join(upload_dir, 'manifest_' + os.path.basename(result) + '.plist')
            with open(manifest_path, 'wb') as f:
                f.write(manifest)

            signed_app = SignedApp()
            signed_app.user_id = current_user.id
            signed_app.app_name = os.path.basename(ipa_path)
            signed_app.bundle_id = bundle_id
            signed_app.ipa_path = result
            signed_app.plist_path = manifest_path
            signed_app.installation_url = f"itms-services://?action=download-manifest&url={request.host_url}manifest/{os.path.basename(manifest_path)}"
            signed_app.icon_url = icon_url
            signed_app.full_size_icon_url = full_size_icon_url
            # Set fixed 30-day expiration
            signed_app.expiration_date = datetime.utcnow() + timedelta(days=30)
            
            db.session.add(signed_app)
            db.session.commit()
            
            flash('App signed successfully')
        else:
            flash(f'Error signing app: {str(result)}')

    except Exception as e:
        flash(f'Signing process failed: {str(e)}')

    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/manifest/<filename>')
def serve_manifest(filename):
    app = None
    upload_path = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'], filename)
    
    if current_user.is_authenticated:
        app = SignedApp.query.filter_by(
            user_id=current_user.id,
            plist_path=upload_path
        ).first()
    else:
        app = SignedApp.query.filter(
            SignedApp.is_public == True,
            SignedApp.plist_path.contains(filename),
            SignedApp.expiration_date > datetime.utcnow()
        ).first()
        
    if not app:
        abort(404)
        
    return send_file(upload_path, mimetype='application/xml')

@app.route('/download/<filename>')
def download_file(filename):
    # Find the associated app
    upload_path = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'], filename)
    
    if current_user.is_authenticated:
        app = SignedApp.query.filter(
            SignedApp.user_id == current_user.id,
            (SignedApp.ipa_path == upload_path) | 
            (SignedApp.icon_url.contains(filename)) | 
            (SignedApp.full_size_icon_url.contains(filename))
        ).first()
    else:
        app = SignedApp.query.filter(
            SignedApp.is_public == True,
            SignedApp.expiration_date > datetime.utcnow(),
            (SignedApp.ipa_path == upload_path) | 
            (SignedApp.icon_url.contains(filename)) | 
            (SignedApp.full_size_icon_url.contains(filename))
        ).first()
    
    if not app:
        abort(404)
    
    mime_type = 'application/octet-stream'
    if filename.endswith('.png'):
        mime_type = 'image/png'
    elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
        mime_type = 'image/jpeg'
    elif filename.endswith('.plist'):
        mime_type = 'application/xml'
    elif filename.endswith('.ipa'):
        mime_type = 'application/octet-stream'
    
    return send_file(
        upload_path,
        mimetype=mime_type,
        as_attachment=True if mime_type == 'application/octet-stream' else False
    )

@app.route('/toggle-share/<int:app_id>', methods=['POST'])
@login_required
def toggle_share(app_id):
    app = SignedApp.query.filter_by(id=app_id, user_id=current_user.id).first_or_404()
    app.is_public = not app.is_public
    db.session.commit()
    flash('Sharing settings updated successfully')
    return redirect(url_for('dashboard'))

@app.route('/shared/<token>')
def shared_app(token):
    app = SignedApp.query.filter_by(
        share_token=token,
        is_public=True
    ).first_or_404()
    
    if app.expiration_date < datetime.utcnow():
        abort(410)  # Gone - resource no longer available
        
    return render_template('shared_app.html', app=app, now=datetime.utcnow())
