from . import db

class SurveyChoice(db.Model):
    __tablename__ = "survey_choices"
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey("survey_questions.id"))
    text = db.Column(db.String(500), nullable=False)

    question = db.relationship("SurveyQuestion", back_populates="choices")