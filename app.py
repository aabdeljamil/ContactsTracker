from flask import Flask, render_template, request, redirect, url_for, flash
import os
from models import db, Contact, User
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')

# Database configuration for local development. COMMENT THE FOLLOWING LINE IF USING POSTGRESQL
# connString = ''
# with open('dbConnectionString.txt') as stream:
#     connString = stream.readline()
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', connString)

# Database configuration for production (PostgreSQL)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        user = User(username=username, is_admin=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

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

@app.route('/contact/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    db.session.rollback()  # Clear any existing session state
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'] or None
        phone = request.form.get('phone')
        rating = request.form.get('rating', type=int)
        comments = request.form.get('comments')

        if Contact.query.filter_by(email=email).first() and email:
            flash("Email already exists", 'danger')
            return render_template('contact.html', action="Add", contact={}, name=name, phone=phone, rating=rating, comments=comments)

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
        flash('Contact added!', 'success')
        return redirect(url_for('contacts'))
    
    return render_template('contact.html', action="Add", contact={})

@app.route('/contact/edit/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    if contact.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this contact.', 'danger')
        return redirect(url_for('contacts'))
    
    if request.method == 'POST':
        contact.name = request.form['name']
        contact.email = request.form['email'] or None
        contact.phone = request.form.get('phone')
        contact.rating = request.form.get('rating', type=int)
        contact.comments = request.form.get('comments')
        db.session.commit()

        flash("Contact updated successfully!", "success")
        return redirect(url_for("contacts"))
        
    return render_template('contact.html', action="Edit", contact=contact)

@app.route("/contact/delete/<int:contact_id>", methods=["GET", "POST"])
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    db.session.delete(contact)
    db.session.commit()
    flash("Contact deleted successfully!", "success")
    return redirect(url_for("contacts"))

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(Exception)
def handle_exception(e):
    # Log the exception
    app.logger.error(f"Unhandled Exception: {e}")
    # Show a friendly error page
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    app.run()