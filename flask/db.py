"""
File: db.py
Purpose: This file defines the database models for Project Bermuda.
Creation Date: 2024-11-06
Authors: Stephen Swanson, Alexandr Iapara

This file is part of Project Bermuda, which includes user authentication, challenge management, and terminal session tracking.
The database models defined here are used to store and manage user data, challenge solves, and terminal sessions.

Modifications:
- 2024-11-06: Added start of database file
- 2024-11-12: Added get_db_id, is_active, get_id, is_authenticated, and is_anonymous methods to User model
- 2024-11-27: Connected challanges page to database
- 2024-11-30: Fixed submit correction flag not functioning correctly with database
- 2024-12-5: Added ssh credential model
"""

# Import necessary libraries and modules
from sqlalchemy import Integer, String, ForeignKey, DateTime
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from sqlalchemy.sql import func
from bcrypt import gensalt, hashpw, checkpw

# Define the base class for declarative models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with the custom base class
db = SQLAlchemy(model_class=Base)

# Define the User model
class User(db.Model):
    """
    User model to store user information.
    
    Attributes:
        id (int): Primary key.
        email (str): User's email address.
        container_name (str): Name of the user's container.
        active (bool): User's active status.
        last_seen (datetime): Timestamp of the last time the user was seen.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    container_name: Mapped[str] = mapped_column(String(100), nullable=True)
    active: Mapped[bool] = mapped_column(nullable=True)
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())

    def get_db_id(self):
        """
        Get the database ID of the user.
        
        Returns:
            int: User's database ID.
        """
        return self.id

    def is_active(self):
        """
        Check if the user is active.
        
        Returns:
            bool: True if the user is active, False otherwise.
        """
        return True

    def get_id(self):
        """
        Get the user's email as the ID for Flask-Login.
        
        Returns:
            str: User's email address.
        """
        return self.email

    def is_authenticated(self):
        """
        Check if the user is authenticated.
        
        Returns:
            bool: True if the user is authenticated, False otherwise.
        """
        return True

    def is_anonymous(self):
        """
        Check if the user is anonymous.
        
        Returns:
            bool: False, as anonymous users are not supported.
        """
        return False

# Define the Challenge_Solve model
class Challenge_Solve(db.Model):
    """
    Challenge_Solve model to store information about solved challenges.
    
    Attributes:
        id (int): Primary key.
        challenge_id (str): Identifier for the challenge.
        user_id (int): Foreign key referencing the user who solved the challenge.
        user (User): Relationship to the User model.
    """
    __tablename__ = "challenge_solves"
    id: Mapped[int] = mapped_column(primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(50))  # reasonable length for a challenge identifier
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user: Mapped[User] = relationship("User", backref="challenge_solved")

# Define the Terminal_Session model
class Terminal_Session(db.Model):
    """
    Terminal_Session model to store information about terminal sessions.
    
    Attributes:
        id (int): Primary key.
        fd (int): File descriptor for the terminal session.
        pid (int): Process ID for the terminal session.
        user_id (int): Foreign key referencing the user associated with the terminal session.
        user (User): Relationship to the User model.
    """
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
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=True)
    ssh_key: Mapped[str] = mapped_column(String(5000), nullable=True)
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
