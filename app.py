
from flask import Flask, render_template, request, redirect, url_for, flash
import os
from models import db, Contact, User
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')


# Configure the PostgreSQL database URI: replace with your actual credentials
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://username:password@host:port/dbname')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize db with app
db.init_app(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Make User model compatible with Flask-Login
class UserLogin(UserMixin, User):
    pass

@app.route('/')
@login_required
def index():
    if current_user.is_admin:
        contacts = Contact.query.all()
    else:
        contacts = Contact.query.filter_by(user_id=current_user.id).all()
    total_contacts = len(contacts)
    avg_rating = None
    ratings = [c.rating for c in contacts if c.rating is not None]
    if ratings:
        avg_rating = round(sum(ratings) / len(ratings), 2)
    return render_template('index.html', contacts=contacts, total_contacts=total_contacts, avg_rating=avg_rating)

@app.route('/contacts')
@login_required
def contacts():
    if current_user.is_admin:
        contacts = Contact.query.all()
    else:
        contacts = Contact.query.filter_by(user_id=current_user.id).all()
    return render_template('contacts.html', contacts=contacts)

# Simple login route for demonstration (replace with secure logic in production)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Route to show add contact form
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone')
        rating = request.form.get('rating', type=int)
        comments = request.form.get('comments')
        contact = Contact(
            name=name,
            email=email,
            phone=phone,
            rating=rating,
            comments=comments,
            user_id=current_user.id
        )
        db.session.add(contact)
        db.session.commit()
        flash('Contact added!')
        return redirect(url_for('index'))
    return render_template('add_contact.html')

if __name__ == '__main__':
    app.run(debug=True)
