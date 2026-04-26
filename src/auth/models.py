from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, role="admin"):
        self.id = id
        self.username = username
        self.role = role

    def get_id(self):
        return str(self.id)
