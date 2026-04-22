from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    score = db.Column(db.Integer)
    status = db.Column(db.String(50))
    ml_confidence = db.Column(db.Float)
    domain_age = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "score": self.score,
            "status": self.status,
            "ml_confidence": self.ml_confidence,
            "domain_age": self.domain_age,
            "timestamp": self.timestamp.isoformat()
        }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # user, business, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    website_url = db.Column(db.String(2048), nullable=False)
    domain = db.Column(db.String(255), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=False)
    screenshot_path = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="open")  # open, under_review, resolved
    admin_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    reporter = db.relationship("User", backref=db.backref("reports", lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "reporter": self.reporter.username if self.reporter else "unknown",
            "reporter_role": self.reporter.role if self.reporter else "user",
            "website_url": self.website_url,
            "domain": self.domain,
            "title": self.title,
            "details": self.details,
            "screenshot_path": self.screenshot_path,
            "status": self.status,
            "admin_note": self.admin_note,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ReportVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("report.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    vote = db.Column(db.String(30), nullable=False)  # phishing, non_phishing
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    report = db.relationship("Report", backref=db.backref("votes", lazy=True, cascade="all, delete-orphan"))
    user = db.relationship("User", backref=db.backref("report_votes", lazy=True))

    __table_args__ = (db.UniqueConstraint("report_id", "user_id", name="unique_report_vote_per_user"),)


class BusinessVerificationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    website_domain = db.Column(db.String(255), nullable=False, unique=True)
    business_name = db.Column(db.String(255), nullable=False)
    proof_details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="pending")  # pending, approved, rejected
    reviewed_by_admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    review_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    business_user = db.relationship("User", foreign_keys=[business_user_id], backref=db.backref("verification_requests", lazy=True))
    reviewed_by_admin = db.relationship("User", foreign_keys=[reviewed_by_admin_id], backref=db.backref("reviewed_verifications", lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "business_user": self.business_user.username if self.business_user else None,
            "website_domain": self.website_domain,
            "business_name": self.business_name,
            "proof_details": self.proof_details,
            "status": self.status,
            "review_note": self.review_note,
            "created_at": self.created_at.isoformat(),
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
        }