from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .contact import Contact
from .user import User
from .surveyResponse import SurveyResponse
from .surveyQuestion import SurveyQuestion
from .surveyChoice import SurveyChoice