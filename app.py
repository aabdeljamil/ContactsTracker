from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from models import db, Contact, User
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_migrate import Migrate
from sqlalchemy import desc, asc
import pickle
import base64
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key')

###################################################################################################################
# Database configuration for local development.
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# connString = ''
# with open('dbConnectionString.txt') as stream:
#     connString = stream.readline()
# app.config['SQLALCHEMY_DATABASE_URI'] = connString
###################################################################################################################

###################################################################################################################
# Database configuration for production (PostgreSQL)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
###################################################################################################################

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CLIENT_SECRETS_FILE = 'client_secret_831213249565-usq2ual4ma5dhsmg01j6lnoa80r7gmoj.apps.googleusercontent.com.json'
client_config = {
    "web": {
        "client_id": os.environ['GOOGLE_CLIENT_ID'],
        "client_secret": os.environ['GOOGLE_CLIENT_SECRET'],
        "redirect_uris": [url_for('oauth2callback', _external=True)],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }
}

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

@app.route('/authorize')
def authorize():
    # Testing
    # flow = Flow.from_client_secrets_file(
    #     CLIENT_SECRETS_FILE,
    #     scopes=SCOPES,
    #     redirect_uri=url_for('oauth2callback', _external=True)
    # )

    # Production
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']

    # Testing
    # flow = Flow.from_client_secrets_file(
    #     CLIENT_SECRETS_FILE,
    #     scopes=SCOPES,
    #     state=state,
    #     redirect_uri=url_for('oauth2callback', _external=True)
    # )

    # Production
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    with open('token.pickle', 'wb') as token:
        pickle.dump(creds, token)

    return 'Authorization successful! You can now send emails.'

def send_email(to_email, subject, html_content):
    with open('token.pickle', 'rb') as token:
        creds = pickle.load(token)
    service = build('gmail', 'v1', credentials=creds)
    message = MIMEText(html_content, 'html')
    message['to'] = to_email
    message['from'] = creds._client_id  # or your Gmail address
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    service.users().messages().send(userId='me', body={'raw': raw_message}).execute()

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
    avg_rating = None
    avg_rating_all = None
    total_contacts_all = None

    if current_user.is_admin:
        contacts_all = Contact.query.all()
        total_contacts_all = len(contacts_all)
        ratings_all = [c.rating for c in contacts_all if c.rating is not None]

        if ratings_all:
            avg_rating_all = round(sum(ratings_all) / len(ratings_all), 2)

    contacts = Contact.query.filter_by(user_id=current_user.id).all()

    return render_template('index.html', total_contacts_all=total_contacts_all, total_contacts=len(contacts), avg_rating=current_user.avg_rating(), avg_rating_all=avg_rating_all)

@app.route('/contacts')
@login_required
def contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id).order_by(desc(Contact.id)).all()
    return render_template('contacts.html', contacts=contacts)

@app.route('/allcontacts')
@login_required
def allContacts():
    if current_user.is_admin:
        contacts = Contact.query.order_by(desc(Contact.id)).all()
    else:
        flash('You do not have permission to view all contacts.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('allContacts.html', contacts=contacts)

@app.route('/users')
@login_required
def users():
    if current_user.is_admin:
        users = User.query.order_by(asc(User.username)).all()
    else:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('users.html', users=users)

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot delete an admin user.', 'danger')
        return redirect(url_for('users'))
    
    if user.contacts:
        flash('Cannot delete user with associated contacts. Please delete their contacts first.', 'danger')
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('users'))

@app.route('/user/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot change your own admin status.', 'danger')
        return redirect(url_for('users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"User '{user.username}' admin status changed to {'Admin' if user.is_admin else 'User'}.", 'success')
    return redirect(url_for('users'))

@app.route('/contact/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    # db.session.rollback()  # Clear any existing session state
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

        # send email notification if email is provided
        if email:
            try:
                subject = "Generation Islam - Follow Up"
                html_content = "Assalamu Alaikum,<br><br>It was nice speaking with you at one of the Generation Islam booths ran by "\
                    "Hizb Ut Tahrir. Here are some useful links and documents to check out which are relevant to "\
                    "what we discussed, and also links to our social media. We'd be grateful if you can give us a follow.<br><br>"\
                    "Generation Islam Instagram: https://www.instagram.com/generation_islam<br>"\
                    "Generation Islam TikTok: https://www.tiktok.com/@generation_islam<br>"\
                    "Generation Islam X (Twitter): https://x.com/Gen_Islam2025<br>"\
                    "Generation Islam Telegram: https://t.me/generation_islam<br><br>"\
                    "Central Media Office of HT: https://www.hizb-ut-tahrir.info/<br>"\
                    "Literature of HT: https://www.hizb-ut-tahrir.info/en/index.php/latest-articles/16477.html<br>"\
                    "Membership in HT: https://www.hizb-ut-tahrir.info/en/index.php/latest-articles/7983.html<br>"\
                    "HT's Work: https://www.hizb-ut-tahrir.info/en/index.php/definition-of-ht/item/7984-hizb-ut-tahrir%E2%80%99s-work"\
                    "<br><br>Please don't hesitate to reach out if you have any questions "\
                    "or want to further discuss something.<br><br>Best regards,<br>Hizb Ut Tahrir - America"
                send_email(email, subject, html_content)
                app.logger.info(f"Email sent to {email} via Gmail API")
            except Exception as e:
                app.logger.error(f"Failed to send email via Gmail API: {e}")
                flash('Failed to send email notification.', 'warning')
                
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