from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from collections import defaultdict
from dotenv import load_dotenv
import os
import base64
import pandas as pd
import io
import os

app = Flask(__name__)
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///capstone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")  # Required for flashing messages and session management
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
FERNET_KEY = os.environ.get("FERNET_KEY")

if not FERNET_KEY:
    raise ValueError("FERNET_KEY is not set in environment variables")

cipher = Fernet(FERNET_KEY.encode())

db = SQLAlchemy(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

FERNET_KEY = os.environ.get("FERNET_KEY")

if not FERNET_KEY:
    raise ValueError("FERNET_KEY is not set in environment variables")

cipher = Fernet(FERNET_KEY.encode())

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()  # Convert to bytes, encrypt, then back to string

def decrypt_data(data):
    return cipher.decrypt(data.encode()).decode()  # Convert to bytes, decrypt, then back to string

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_username = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

def log_action(username, action, ip_address=None):
    log = SecurityLog(admin_username=username, action=action, ip_address=ip_address)
    db.session.add(log)
    db.session.commit()

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Store hashed passwords in production

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    position = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(300), nullable=False)
    image_url = db.Column(db.String(300), nullable=False)
    image_blob = db.Column(db.LargeBinary)
    nimetype = db.Column(db.Text, nullable=False) #* for the image type e.g. jpeg, jpg, png
    vote_count = db.Column(db.Integer, default=0)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(50), nullable=False)
    candidate_name = db.Column(db.String(300), nullable=False)

def create_tables():
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            hashed_password = generate_password_hash('admin123')
            default_admin = Admin(username='admin', password=hashed_password)
            db.session.add(default_admin)
            db.session.commit()

# Client Side
@app.route('/')
def index():
    return render_template('clients/index.html')

@app.route('/check-user', methods=['POST'])
def check_user():
    data = request.json
    user_id = data.get('userId')

    # Check 1: Must start with 'CA'
    if not user_id or not user_id.startswith('CA'):
        return jsonify({'status': 'error', 'message': 'Invalid user ID. Must start with CA'}), 400

    # Check 2: Has the user already voted?
    existing_vote = Vote.query.filter_by(user_id=user_id).first()
    if existing_vote:
        return jsonify({'status': 'error', 'message': 'User ID has already voted'}), 400

    # # Check 3: Is this user ID in the valid clients table?
    # valid_client = ValidClient.query.filter_by(client_id=user_id).first()
    # if not valid_client:
    #     return jsonify({'status': 'error', 'message': 'User ID is not authorized'}), 403

    # All checks passed
    return jsonify({'status': 'success', 'message': 'User ID is valid'}), 200


@app.route('/vote-pres')
def vote_pres():
    id_data = request.args.get('id')
    candidates = Candidate.query.all()
    candidates_by_position = defaultdict(list)

    for candidate in candidates:
        decrypted_name = decrypt_data(candidate.name)
        candidate.name = decrypted_name
        
        # Convert the image_blob to a base64 string if it exists
        if candidate.image_blob:
            candidate.image_base64 = base64.b64encode(candidate.image_blob).decode('utf-8')
        else:
            candidate.image_base64 = None

        candidates_by_position[candidate.position].append(candidate)

    print(candidates_by_position)  # Add this line for debugging
    return render_template('clients/vote-pres.html', id_data=id_data, candidates_by_position=candidates_by_position)

@app.route('/submit-votes', methods=['POST'])
def submit_votes():
    data = request.json  
    user_id = data.get('userId')  
    selections = data.get('selections', {})  

    for position, candidate_name in selections.items():
        # Find candidate by decrypting each stored name
        candidates = Candidate.query.all()
        selected_candidate = None
        
        for candidate in candidates:
            if decrypt_data(candidate.name) == candidate_name:
                selected_candidate = candidate
                break
        
        if selected_candidate:
            selected_candidate.vote_count += 1  # Increment vote count

            # Encrypt the vote before storing
            encrypted_name = encrypt_data(candidate_name)
            vote = Vote(user_id=user_id, position=position, candidate_name=encrypted_name)
            db.session.add(vote)

    db.session.commit()  
    return jsonify({'status': 'success'})

# Admin Side

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Find the admin by username
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            session['admin'] = True
            flash('Login successful', 'success')
            log_action(username, "Logged in", request.remote_addr)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    log_action('admin', "Logged out", request.remote_addr)
    session.pop('admin', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))

    admin = Admin.query.first()
    
    if request.method == 'POST':
        new_username = request.form['username']
        old_password = request.form['old_password']
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check old password
        if not check_password_hash(admin.password, old_password):
            flash('Incorrect current password!', 'danger')
            return redirect(url_for('admin_settings'))

        # Check new password match
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger')
            return redirect(url_for('admin_settings'))

        admin.username = new_username
        admin.password = generate_password_hash(new_password)
        db.session.commit()
        log_action(admin.username, "Changed Password", request.remote_addr)

        flash('Settings updated successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('admin/admin_settings.html', admin=admin)


@app.route('/admin/votes')
def admin_votes():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))
    user_id = request.args.get('user_id')
    votes = Vote.query.filter_by(user_id=user_id).all() if user_id else Vote.query.all()

    for vote in votes:
        vote.candidate_name = decrypt_data(vote.candidate_name)
    return render_template('admin/admin_votes.html', votes=votes)

@app.route('/admin/votes/delete_all', methods=['POST'])
def delete_all_votes():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))

    # Delete all votes
    db.session.query(Vote).delete()

    # Reset vote count of all candidates
    candidates = Candidate.query.all()
    for candidate in candidates:
        candidate.vote_count = 0

    db.session.commit()
    log_action('admin', "Deleted all votes and reset vote counts", request.remote_addr)
    flash('All votes and vote counts deleted successfully', 'success')
    return redirect(url_for('admin_votes'))


@app.route('/admin/votes/export')
def export_votes():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))
        
    votes = Vote.query.all()
    
    data = [{
        'ID': v.id,
        'User ID': v.user_id,
        'Position': v.position,
        'Candidate Name': decrypt_data(v.candidate_name)  # Decrypt candidate name
    } for v in votes]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Votes')
    
    output.seek(0)
    log_action('admin', "Exported votes to Excel", request.remote_addr)
    return send_file(output, download_name='votes.xlsx', as_attachment=True)


from collections import defaultdict, OrderedDict

@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))

    candidates = Candidate.query.all()

    # Decrypt names
    for candidate in candidates:
        candidate.name = decrypt_data(candidate.name)

    # Group candidates by position
    grouped_candidates = defaultdict(list)
    for candidate in candidates:
        grouped_candidates[candidate.position].append(candidate)

    # Sort each group by vote count descending
    for position in grouped_candidates:
        grouped_candidates[position].sort(key=lambda c: c.vote_count, reverse=True)

    # Define custom position order
    position_order = [
        "President",
        "Vice President",
        "Secretary",
        "Treasurer",
        "Public Relations Officer"
    ]

    # Reorder grouped_candidates based on position_order
    ordered_grouped_candidates = OrderedDict()
    for position in position_order:
        if position in grouped_candidates:
            ordered_grouped_candidates[position] = grouped_candidates[position]

    return render_template('admin/dashboard.html', grouped_candidates=ordered_grouped_candidates)


@app.route('/candidates', methods=['GET', 'POST']) # * updated
def manage_candidates():
    if request.method == 'POST':
        position = request.form['position']
        name = request.form['name']

        # Get uploaded image
        file = request.files['image_url']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_data = file.read()  # Read first while stream is open
            file.stream.seek(0)       # Reset the stream position so save() works
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)

            image_url = f'uploads/{filename}'
            encrypted_name = encrypt_data(name)

            new_candidate = Candidate(
                position=position,
                name=encrypted_name,
                image_url=image_url,
                image_blob=image_data,
                nimetype=file.mimetype,
            )
            db.session.add(new_candidate)
            db.session.commit()
            log_action('admin', f"Added candidate for {position}", request.remote_addr)
            flash('Candidate added successfully!', 'success')
        else:
            flash('Invalid file type!', 'danger')

        return redirect(url_for('manage_candidates'))

    candidates = Candidate.query.all()
    
    # Decrypt names before displaying
    for candidate in candidates:
        candidate.name = decrypt_data(candidate.name)

    return render_template('admin/candidates_setting.html', candidates=candidates)

@app.route('/delete/<int:id>')
def delete_candidate(id):
    candidate = Candidate.query.get_or_404(id)
    db.session.delete(candidate)
    db.session.commit()
    log_action('admin', f"Deleted candidate with ID {id}", request.remote_addr)
    return redirect(url_for('manage_candidates'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_candidate(id):
    candidate = Candidate.query.get_or_404(id)
    
    candidate.name = decrypt_data(candidate.name)
    
    if request.method == 'POST':
        # Update candidate's position
        candidate.position = request.form['position']
        
        # Encrypt the name before saving it
        candidate.name = encrypt_data(request.form['name'])
        
        # Handle file upload for the image (if a new file is uploaded)
        file = request.files.get('image_url')  # 'image_url' is the name attribute of your file input
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_data = file.read()  # Read the image as binary data
            file.stream.seek(0)       # Reset the stream position so save() works
            
            # Save the image file to the server
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            
            # Update the image URL to the new file path
            candidate.image_url = f'uploads/{filename}'
            
            # Update the image_blob with the new image data
            candidate.image_blob = image_data
            candidate.nimetype = file.mimetype  # Store the MIME type for reference
        
        db.session.commit()
        log_action('admin', f"Updated candidate with ID {id}", request.remote_addr)
        flash('Candidate updated successfully!', 'success')
        return redirect(url_for('manage_candidates'))

    # For GET requests, render the edit form with the candidate's current details
    return render_template('admin/edit.html', candidate=candidate)

@app.route('/admin/security-log')
def security_log():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))

    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).all()
    return render_template('admin/security_log.html', logs=logs)

@app.route('/admin/logs/export')
def export_logs():
    if 'admin' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('admin_login'))

    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).all()

    log_action('admin', 'Exported security logs', request.remote_addr)

    data = [{
        'ID': log.id,
        'Username': log.admin_username,
        'Action': log.action,
        'IP Address': log.ip_address,
        'Timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Logs')
    output.seek(0)

    return send_file(output, download_name='security_logs.xlsx', as_attachment=True)

if __name__ == '__main__':
    create_tables()
    app.run(host="0.0.0.0", port=5000) #! ssl_context=('cert.pem', 'key.pem') remove for now for production

# FIXME: pip install -r requirements.txt