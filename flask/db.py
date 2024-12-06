from sqlalchemy import Integer, String, ForeignKey,DateTime
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from sqlalchemy.sql import func
from bcrypt import gensalt, hashpw, checkpw


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    container_name: Mapped[str] = mapped_column(String(100), nullable=True)
    active: Mapped[bool] = mapped_column(nullable=True)
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())

    def get_db_id(self):
        return self.id

    def is_active(self):
        return True

    # for flask login, we're using email as the ID
    def get_id(self):
        return self.email

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False


class Challenge_Solve(db.Model):
    __tablename__ = "challenge_solves"
    id: Mapped[int] = mapped_column(primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(50))  # reasonable length for a challenge identifier
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user: Mapped[User] = relationship("User", backref="challenge_solved")

class Terminal_Session(db.Model):
    __tablename__ = "webterm_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    fd: Mapped[int] = mapped_column()
    pid: Mapped[int] = mapped_column()
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)

    # Establish a relationship to the User model
    user: Mapped[User] = relationship("User", backref="terminal_sessions")

class SSH_Cred(db.Model):
    __tablename__ = "ssh_creds"
    id: Mapped[int] = mapped_column(primary_key=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    ssh_key: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)

    # Establish a relationship to the User model
    user: Mapped[User] = relationship("User", backref="ssh_cred")

    def set_password(self, password: str):
        """Hash and store the password using bcrypt."""
        salt = gensalt()
        self.hashed_password = hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Verify the provided password matches the hashed password."""
        return checkpw(password.encode("utf-8"), self.hashed_password.encode("utf-8"))
