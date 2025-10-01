from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .contact import Contact
from .user import User
from .surveyResponse import surveyResponse
from .surveyQuestion import surveyQuestion
from .surveyChoice import surveyChoice