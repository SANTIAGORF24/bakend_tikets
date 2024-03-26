from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import secrets
import string

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Generar una clave secreta segura para JWT
key_length = 64
characters = string.ascii_letters + string.digits + string.punctuation
secret_key = ''.join(secrets.choice(characters) for _ in range(key_length))
app.config['JWT_SECRET_KEY'] = secret_key

db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    topics = db.relationship('Topic', backref='user', lazy='dynamic')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.first_name}', '{self.last_name}')"
    
class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Permitir valores nulos

    def __repr__(self):
        return f"Topic('{self.name}')"
    

with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'El usuario ya existe'}), 409
    # Encriptar la contraseña
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    # Crear un nuevo usuario
    new_user = User(username=username, password=hashed_password.decode('utf-8'), email=email, first_name=first_name, last_name=last_name)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # Buscar el usuario en la base de datos
    user = User.query.filter_by(username=username).first()
    if user:
        # Verificar la contraseña
        password_bytes = password.encode('utf-8')
        if bcrypt.checkpw(password_bytes, user.password.encode('utf-8')):
            access_token = create_access_token(identity=user.id)
            return jsonify({'access_token': access_token, 'user_email': user.email}), 200  # Devuelve el correo del usuario junto con el token de acceso
        else:
            return jsonify({'message': 'Contraseña inválida'}), 401
    else:
        return jsonify({'message': 'Usuario no encontrado'}), 404

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        return jsonify({'email': user.email}), 200
    else:
        return jsonify({'message': 'Usuario no encontrado'}), 404

@app.route('/topics', methods=['GET'])
def get_topics():
    app.logger.info('Solicitud GET recibida en /topics')
    topics = Topic.query.all()
    output = []
    for topic in topics:
        output.append({'id': topic.id, 'name': topic.name})  # Excluir user_id
    app.logger.info(f'Respuesta devuelta: {output}')
    return jsonify({'topics': output})


@app.route('/topics', methods=['POST'])
def add_topic():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'message': 'El nombre del tema es requerido'}), 400
    new_topic = Topic(name=name)
    db.session.add(new_topic)
    db.session.commit()
    return jsonify({'message': 'Tema agregado correctamente'}), 201

if __name__ == '__main__':
    app.run(debug=True)
