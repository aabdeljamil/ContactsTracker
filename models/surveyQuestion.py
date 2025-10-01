from . import db

class SurveyQuestion(db.Model):
    __tablename__ = "survey_questions"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)

    choices = db.relationship("SurveyChoice", back_populates="question", cascade="all, delete-orphan")