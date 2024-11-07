from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    balance = db.Column(db.Integer, default=1000)

class Nomination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    nominee = db.Column(db.String(150), nullable=False)

# Routes for Authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully with 1000 units balance!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already exists. Please try again.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('nominate'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Here, you would ideally send an email to reset the password
            flash('Password reset instructions have been sent to your email.', 'info')
        else:
            flash('No account found with that email.', 'danger')
    return render_template('forgot_password.html')

# Route for Nomination
@app.route('/nominate', methods=['GET', 'POST'])
def nominate():
    if 'user_id' not in session:
        flash('Please log in to nominate.', 'warning')
        return redirect(url_for('login'))

    categories = ['Poet of the year', 'Content Creator of the year', 'Film Producer of the year']
    
    if request.method == 'POST':
        category = request.form['category']
        nominee = request.form['nominee']
        user = User.query.get(session['user_id'])

        if user.balance >= 50:
            nomination = Nomination(user_id=user.id, category=category, nominee=nominee)
            user.balance -= 50
            db.session.add(nomination)
            db.session.commit()
            flash(f'{nominee} successfully nominated in {category} category!', 'success')
        else:
            flash('Insufficient balance for nomination.', 'danger')
    return render_template('nominate.html', categories=categories)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Error handling
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates tables if they do not exist
    app.run(debug=True)
