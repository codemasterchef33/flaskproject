from flask import Flask, request, jsonify, current_app, abort ,send_from_directory, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import timedelta
from functools import wraps
from flask import session
import jwt
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/FileShare"
mongo = PyMongo(app)
s = URLSafeTimedSerializer('Thisisasecret!')

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.environ.get('EMAIL_USER', 'sonukhulbe27@gmail.com'),
    "MAIL_PASSWORD": os.environ.get('EMAIL_PASSWORD', 'please enter your email address pasword or apppassword'),
}

app.config.update(mail_settings)
mail = Mail(app)

app.config['UPLOAD_FOLDER'] = 'C:\\Users\\manis\\Downloads\\Polling_Api-main\\Polling_Api-main'

# UPLOAD_FOLDER = r'C:\Users\manis\Downloads\Polling_Api-main\Polling_Api-main'


s3 = boto3.client('s3', region_name='us-east-1',
                  aws_access_key_id='please enter your AWS access key',
                  aws_secret_access_key='please enter your AWS secret access key')



ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/user1/signup', methods=['POST'])
def user1_signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    existing_user = mongo.db.ops_users.find_one({'$or': [{'username': username}, {'email': email}]})
    if existing_user:
        return jsonify({'message': 'Username or email already exists'}), 409

    hashed_password = generate_password_hash(password)
    mongo.db.ops_users.insert_one({'username': username, 'email': email, 'password': hashed_password})

    return jsonify({'message': 'User created successfully'}), 201


@app.route('/user1/login', methods=['POST'])
def user1_login():
    data = request.json
    username = data.get('username')
    email = data.get('email')  
    password = data.get('password')
    

    user = mongo.db.ops_users.find_one({'$or': [{'username': username}, {'email': email}]})
    if user and check_password_hash(user['password'], password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid username, email, or password'}), 401



# @app.route('/user1/upload', methods=['POST'])
# def upload_file():
    
  

#     if 'file' not in request.files:
#         return jsonify({'message': 'No file part'}), 400
    
#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({'message': 'No selected file'}), 400
    
#     if file and allowed_file(file.filename):
#         filename = secure_filename(file.filename)
#         file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#         return jsonify({'message': 'File uploaded successfully'}), 201
#     else:
#         return jsonify({'message': 'Invalid file type'}), 400




@app.route('/user1/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # Upload file to S3 bucket
            s3.upload_fileobj(file, 'expensetracker11', file.filename)
            return jsonify({'message': 'File uploaded successfully'}), 201
        except ClientError as e:
            return jsonify({'message': 'Failed to upload file to S3', 'error': str(e)}), 500
    else:
        return jsonify({'message': 'Invalid file type'}), 400

@app.route('/user2/signup', methods=['POST'])
def user2_signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
   
    existing_user = mongo.db.client_users.find_one({'username': username})
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 409
    
    hashed_password = generate_password_hash(password)
    mongo.db.client_users.insert_one({'username': username, 'email': email, 'password': hashed_password ,'server':'false'})
    
    token = s.dumps(email, salt='email-confirm')
    msg = Message('Confirm Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
    link = url_for('verify_email', token=token, _external=True)
    msg.body = 'Your link is {}'.format(link)
    mail.send(msg)
    
    return jsonify({'message': 'User created successfully. Check your email for verification link'}), 201


@app.route('/user2/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = mongo.db.client_users.find_one({'email': email})
        if user:
            mongo.db.client_users.update_one({'email': email}, {'$set': {'verified': True}})
            return jsonify({'message': 'Email verified successfully'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except:
        return jsonify({'message': 'Invalid or expired token'}), 400

SECRET_KEY = 'passkey'
@app.route('/user2/login', methods=['POST'])
def user2_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = mongo.db.client_users.find_one({'username': username})
    if user and check_password_hash(user['password'], password) and user.get('verified'):
      
        token = jwt.encode({'username': username}, SECRET_KEY, algorithm='HS256')
        return jsonify({'message': 'Login successful', 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid username, password or email not verified'}), 401







S3_BUCKET_NAME = 'expensetracker11'

@app.route('/user2/download/<filename>/<token>', methods=['GET'], endpoint='download_file_by_filename')
def download_file(filename, token):
    try:
       
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if 'user_id' in payload:
            user_id = payload['user_id']
            
            s3 = boto3.client('s3')
            
           
            presigned_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': S3_BUCKET_NAME, 'Key': filename},
                ExpiresIn=3600  
            )
            
     
            return jsonify({'presigned_url': presigned_url}), 200
          
        else:
            abort(400)  
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401





@app.route('/user2/files', methods=['GET'])
def list_files():
    try:
       
        s3 = boto3.client('s3')

        response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME)
    
        files = [obj['Key'] for obj in response.get('Contents', [])]

        return jsonify({'files': files}), 200
    except ClientError as e:
        
        error_message = f"Failed to list files: {e}"
        return jsonify({'message': error_message}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
