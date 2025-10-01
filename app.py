from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from models import db, Contact, User, SurveyResponse, SurveyQuestion, SurveyChoice
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_migrate import Migrate
from sqlalchemy import desc, asc
import pickle
import base64
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'secret123')

###################################################################################################################
# Set to True for local development/testing, False for production
isTesting = False
###################################################################################################################

if isTesting:
    debug = True
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    CLIENT_SECRETS_FILE = 'client_secret_831213249565-usq2ual4ma5dhsmg01j6lnoa80r7gmoj.apps.googleusercontent.com.json'
    connString = ''
    try:
        with open('dbConnectionString.txt') as stream:
            connString = stream.readline()
    except FileNotFoundError:
        print("dbConnectionString.txt file not found. Please create the file with the database connection string.")
    app.config['SQLALCHEMY_DATABASE_URI'] = connString
else:
    debug = False
    client_config = {
        "web": {
            "client_id": os.environ.get('GOOGLE_CLIENT_ID'),
            "client_secret": os.environ.get('GOOGLE_CLIENT_SECRET'),
            "redirect_uris": [os.environ.get('GOOGLE_REDIRECT_URI')],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

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

###############################################################
# OAuth 2.0 Authorization Routes
# One-time setup to get the token.pickle file
# Visit /authorize to authorize the app and generate token.pickle
###############################################################
@app.route('/authorize')
def authorize():
    if (isTesting == True):
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
    else:
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
    
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    session['state'] = state
    return redirect(auth_url)

###################################################
# OAuth 2.0 Callback Route
# This route handles the OAuth 2.0 callback and stores the credentials.
###################################################
@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']

    if (isTesting == True):
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
    else:
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

    flash('Authorization successful! You can now send emails.', 'success')
    return redirect(url_for('index'))

###################################################
# Function to get Gmail service and refresh token if expired
###################################################
def get_gmail_service():
    creds = None
    
    # Load saved credentials
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    # Refresh if expired
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    # If no creds at all, force re-auth
    if not creds or not creds.valid:
        return None

    return build("gmail", "v1", credentials=creds)

###################################################
# Function to send email using Gmail API
###################################################
def send_email(to_email, subject, html_content):
    service = get_gmail_service()
    if not service:
        flash("Authorization required. Please visit /authorize first.", "danger")
        return
    
    message = MIMEText(html_content, 'html')
    message['to'] = to_email
    message['from'] = "me"
    message['subject'] = subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        service.users().messages().send(userId='me', body={'raw': raw_message}).execute()
    except HttpError as error:
        if error.resp.status in [403, 429]:
            app.logger.error("Quota exceeded. Try again tomorrow or use a different sender account.")
            flash('Email quota exceeded. Email not sent.', 'warning')
        else:
            app.logger.error(f"An error occurred: {error}")
            flash('Failed to send email.', 'danger')

#####################################################
# Route for user login
#####################################################
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

#####################################################
# Route for user logout
#####################################################
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#####################################################
# Route for user registration
#####################################################
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

#####################################################
# Route for the home page
#####################################################
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

######################################################
# Route for managing your contacts
######################################################
@app.route('/contacts')
@login_required
def contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id).order_by(desc(Contact.id)).all()
    return render_template('contacts.html', contacts=contacts)

######################################################
# Route for managing all contacts (admin only)
######################################################
@app.route('/allcontacts')
@login_required
def allContacts():
    if current_user.is_admin:
        contacts = Contact.query.order_by(desc(Contact.id)).all()
    else:
        flash('You do not have permission to view all contacts.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('allContacts.html', contacts=contacts, title="All Contacts")

######################################################
# Route for managing users (admin only)
######################################################
@app.route('/users')
@login_required
def users():
    if current_user.is_admin:
        users = User.query.order_by(asc(User.username)).all()
    else:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('users.html', users=users)

#######################################################
# Route for viewing a specific user's contacts (admin only)
#######################################################
@app.route('/user/<int:user_id>/contacts')
@login_required
def user_contacts(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    contacts = Contact.query.filter_by(user_id=user.id).order_by(asc(Contact.id)).all()
    return render_template('allContacts.html', contacts=contacts, title=f"Contacts of {user.username}")

#######################################################
# Route for deleting a user (admin only)
#######################################################
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

#######################################################
# Route for toggling a user's admin status (admin only)
#######################################################
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

#######################################################
# Route for adding contacts
#######################################################
@app.route('/contact/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    # db.session.rollback()  # Clear any existing session state
    questions = SurveyQuestion.query.order_by(asc(SurveyQuestion.id)).all()

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

        # Save survey responses
        for question in questions:
            answer = request.form.get(f"q_{question.id}")
            if answer:
                response = SurveyResponse(
                    contact_id=contact.id,
                    question_id=question.id,
                    answer=answer
                )
                db.session.add(response)
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
            except Exception as e:
                app.logger.error(f"Failed to send email via Gmail API: {e}")
                flash('Failed to send email notification.', 'warning')
                
        flash('Contact added!', 'success')
        return redirect(url_for('contacts'))
    
    return render_template('contact.html', action="Add", contact={}, questions=questions)

#######################################################
# Route for editing contacts
#######################################################
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

#######################################################
# Route for deleting contacts
#######################################################
@app.route("/contact/delete/<int:contact_id>", methods=["GET", "POST"])
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    db.session.delete(contact)
    db.session.commit()
    flash("Contact deleted successfully!", "success")
    return redirect(url_for("contacts"))

#######################################################
# Route for survey report (admin only)
#######################################################
@app.route('/surveyReport')
@login_required
def surveyReport():
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    
    questions = SurveyQuestion.query.order_by(asc(SurveyQuestion.id)).all()
    report_data = []

    for question in questions:
        choices = {choice.text: 0 for choice in question.choices}
        responses = SurveyResponse.query.filter_by(question_id=question.id).all()
        total_responses = len(responses)

        for response in responses:
            if response.answer in choices:
                choices[response.answer] += 1

        report_data.append({
            'question': question.text,
            'choices': choices,
            'total_responses': total_responses
        })

    return render_template('surveyReport.html', report_data=report_data)

#######################################################
# Error Handler for 404 Not Found Error
#######################################################
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

#######################################################
# Error Handler for 500 Internal Server Error
#######################################################
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the exception
    app.logger.error(f"Unhandled Exception: {e}")
    # Show a friendly error page
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=debug)