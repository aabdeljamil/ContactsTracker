from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .contact import Contact
from .user import User