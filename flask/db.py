from sqlalchemy import Integer, String, ForeignKey,DateTime
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    container_name: Mapped[str] = mapped_column(nullable=True)
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
    challenge_id: Mapped[str] = mapped_column()
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    user: Mapped[User] = relationship("User", backref="challenge_solved")


class Terminal_Session(db.Model):
    __tablename__ = "webterm_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    fd: Mapped[int] = mapped_column()
    pid: Mapped[int] = mapped_column()
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)

    # Establish a relationship to the User model
    user: Mapped[User] = relationship("User", backref="terminal_sessions")
