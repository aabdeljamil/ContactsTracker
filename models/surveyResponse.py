from . import db

class SurveyResponse(db.Model):
    __tablename__ = 'survey_responses'
    id = db.Column(db.Integer, primary_key=True)
    contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'))
    question_id = db.Column(db.Integer, db.ForeignKey("survey_questions.id"))
    answer = db.Column(db.String(500), nullable=False)

    contact = db.relationship("Contact", back_populates="survey_responses")
    question = db.relationship("SurveyQuestion")