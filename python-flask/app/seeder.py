import os
import bcrypt
from app.model import User
from app.model import db

salt = bcrypt.gensalt(10)

class Seeder():
    def seedData():
        # User Dataseed
        admin = User(
            username='admin',
            password=bcrypt.hashpw(b'4351f71f7f2094359b9d052f231ccad12556f443', salt),
            role="admin")
        db.session.add(admin)

        reporter = User(
            username='reporter',
            password=bcrypt.hashpw(b'4351f71f7f2094359b9d052f231ccad12556f443', salt),
            role="user")
        db.session.add(reporter)

        db.session.commit()
