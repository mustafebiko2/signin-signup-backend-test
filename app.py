from flask import Flask, make_response, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS  # Import CORS from flask_cors

from models import db, User

# Initialize the Flask application
app = Flask(__name__)
CORS(app)  # Enable CORS for all domains on all routes

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "super-secret"

# Initialize Flask extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Create API instance
api = Api(app)

# User Resource for handling user operations
class Users(Resource):
    # Endpoint to get all users (protected route)
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        if current_user:
            users = User.query.all()
            users_list = [user.to_dict() for user in users]
            body = {
                "count": len(users_list),
                "users": users_list
            }
            return make_response(body, 200)
        else:
            return make_response({"message": "Unauthorized"}, 401)

    # Endpoint to create a new user (sign-up)
    def post(self):
        try:
            # Check if email is already taken
            email = request.json.get('email')
            existing_user = User.query.filter_by(email=email).first()

            if existing_user:
                return make_response({ "message": "Email already taken" }, 422)

            # Create new user
            new_user = User(
                username=request.json.get("username"),
                email=email,
                password=bcrypt.generate_password_hash(request.json.get("password")).decode('utf-8') # decode bcrypt hashed password to string
            )

            db.session.add(new_user)
            db.session.commit()

            # Generate access token for new user
            access_token = create_access_token(identity=new_user.id)

            response = {
                "user": new_user.to_dict(),
                "access_token": access_token
            }

            return make_response(response, 201)

        except Exception as e:
            # Handle exceptions (e.g., database errors, validation errors) and return appropriate responses
            return make_response({"message": str(e)}, 500)

# Endpoint to authenticate a user (sign-in)
@app.route('/signin', methods=['POST'])
def signin():
    try:
        email = request.json.get('email')
        password = request.json.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return make_response({
                "user": user.to_dict(),
                "access_token": access_token
            }, 200)
        else:
            return make_response({ "message": "Invalid credentials" }, 401)

    except Exception as e:
        # Handle exceptions (e.g., database errors, validation errors) and return appropriate responses
        return make_response({"message": str(e)}, 500)

# Add resource to API
api.add_resource(Users, '/users')

if __name__ == '__main__':
    app.run(debug=True)
