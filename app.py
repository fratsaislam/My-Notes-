from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cs50 import SQL
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/images'

db = SQL("sqlite:///site.db")

@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']
        user_notes = db.execute("SELECT * FROM notes WHERE user_id = ?", user_id)
        other_users_notes = db.execute("SELECT * FROM notes WHERE user_id != ?", user_id)
        return render_template('index.html', user_notes=user_notes, other_notes=other_users_notes)
    else:
        notes = db.execute("SELECT * FROM notes")
        return render_template('login_page.html', notes=notes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(user) == 1 and check_password_hash(user[0]['password'], password):
            session['user_id'] = user[0]['id']
            session['username'] = user[0]['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        pfp = request.files['pfp']

        if password != confirmation:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        pfp_filename = secure_filename(pfp.filename)
        pfp.save(os.path.join(app.config['UPLOAD_FOLDER'], pfp_filename))

        db.execute("INSERT INTO users (username, password, pfp) VALUES (?, ?, ?)",
                   username, hashed_password, pfp_filename)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/add_note', methods=['GET', 'POST'])
def add_note():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        note = request.form.get('note')
        image = request.files['image']
        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        else:
            image_filename = None
        user = db.execute("SELECT username, pfp FROM users WHERE id = ?", session['user_id'])
        if user:
            user = user[0]
            db.execute("INSERT INTO notes (title, content, image_file, user_id, username, user_pfp, note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       title, content, image_filename, session['user_id'], user['username'], user['pfp'], note)
        else:
            flash('User not found.', 'danger')
        flash('Note added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_note.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    user_id = session['user_id']
    notes = db.execute("SELECT * FROM notes WHERE user_id = ?", user_id)
    return render_template('dashboard.html', notes=notes)

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]

    if request.method == 'POST':
        if 'change_password' in request.form:
            new_password = request.form.get('new_password')
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
            db.execute("UPDATE users SET password = ? WHERE id = ?", hashed_password, session['user_id'])
            flash('Password updated successfully!', 'success')
        elif 'change_pfp' in request.form:
            pfp = request.files['pfp']
            if pfp:
                pfp_filename = secure_filename(pfp.filename)
                pfp.save(os.path.join(app.config['UPLOAD_FOLDER'], pfp_filename))
                db.execute("UPDATE users SET pfp = ? WHERE id = ?", pfp_filename, session['user_id'])
                flash('Profile picture updated successfully!', 'success')

    user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]
    return render_template('account.html', user=user)

@app.route('/note/<int:note_id>')
def view_note(note_id):
    note = db.execute("SELECT * FROM notes WHERE id = ?", note_id)
    if not note:
        flash('Note not found.', 'danger')
        return redirect(url_for('index'))
    note = note[0]
    return render_template('view_note.html', note=note)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
