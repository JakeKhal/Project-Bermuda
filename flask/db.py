
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    container_name: Mapped[str] = mapped_column() 
    active: Mapped[bool] = mapped_column()


class Terminal_Session(db.Model):
    __tablename__ = "webterm_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    fd: Mapped[int] = mapped_column()
    pid: Mapped[int] = mapped_column()
    user_id: Mapped[User] = mapped_column()


