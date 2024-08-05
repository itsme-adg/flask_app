from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import DECIMAL
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import func
import os
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
import pandas as pd
from sqlalchemy import create_engine
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)
CORS(app)

db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_name = os.getenv('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqldb://root:Admin%40123@10.100.130.76/eod"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', '1234567890') # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)


engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email_id = db.Column(db.String(120), unique=True, nullable=False)
    phone_no = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)


class PnRaw(db.Model):
    __tablename__ = 'pn_raw'
    unique_id = db.Column(db.String(100), primary_key=True)
    payment_notice_id = db.Column(db.String(100))
    contractor_afp_ref = db.Column(db.String(100))
    pn_date_issued_to_contractor = db.Column(db.String(100))
    date_of_application = db.Column(db.String(100))
    purchase_order_id = db.Column(db.String(100))
    region = db.Column(db.String(100))
    exchange_id = db.Column(db.String(100))
    town = db.Column(db.String(100))
    contractor = db.Column(db.String(100))
    polygon_type = db.Column(db.String(100))
    polygon_id = db.Column(db.String(100))
    feature_id = db.Column(db.String(100))
    build_status = db.Column(db.String(100))
    code = db.Column(db.String(100))
    item = db.Column(db.String(255))
    unit = db.Column(db.String(100))
    price = db.Column(db.String(100))
    quantity = db.Column(db.String(100))
    total = db.Column(db.String(100))
    comments = db.Column(db.String(255))
    afp_claim_ok_nok = db.Column(db.String(100))
    nok_reason_code = db.Column(db.String(100))
    approved_quantity = db.Column(db.String(100))
    approved_total = db.Column(db.String(100))
    concate = db.Column(db.String(100))
    qgis_quant = db.Column(db.String(100))
    qgis_rate = db.Column(db.String(100))
    qgis_url = db.Column(db.String(255))
    po_check = db.Column(db.String(100))
    comment = db.Column(db.String(255))


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)


class WorkCat(db.Model):
    __tablename__ = 'work_cat'
    Rate_Code = db.Column(db.String(255), primary_key=True)
    Category = db.Column(db.String(255))

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class SubcontractorRate(db.Model):
    __tablename__ = 'subcontractor_rate'
    id = db.Column(db.Integer, primary_key=True)
    rate_code = db.Column(db.String(10), nullable=False)
    work_category = db.Column(db.String(50), nullable=False)
    rate_type = db.Column(db.String(50), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(50), nullable=False)
    heavy_and_dirty = db.Column(db.String(50), nullable=True)
    include_hnd_in_service_price = db.Column(db.String(3), nullable=True)
    description = db.Column(db.Text, nullable=True)
    afs = db.Column(db.DECIMAL(10, 2), nullable=True)
    bk_comms = db.Column(db.DECIMAL(10, 2), nullable=True)
    ccg = db.Column(db.DECIMAL(10, 2), nullable=True)
    jk_comms = db.Column(db.DECIMAL(10, 2), nullable=True)
    jdc = db.Column(db.DECIMAL(10, 2), nullable=True)
    jto = db.Column(db.DECIMAL(10, 2), nullable=True)
    nola = db.Column(db.DECIMAL(10, 2), nullable=True)
    rollo = db.Column(db.DECIMAL(10, 2), nullable=True)
    salcs = db.Column(db.DECIMAL(10, 2), nullable=True)
    upscale = db.Column(db.DECIMAL(10, 2), nullable=True)
    vsl = db.Column(db.DECIMAL(10, 2), nullable=True)
    vus = db.Column(db.DECIMAL(10, 2), nullable=True)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}



class ClientRate(db.Model):
    __tablename__ = 'client_rate'
    rate_code = db.Column(db.String(50), primary_key=True)
    rate_type = db.Column(db.String(255))
    item = db.Column(db.String(255))
    unit = db.Column(db.String(50))
    heavy_and_dirty = db.Column(db.String(25))
    include_hnd_in_service_price = db.Column(db.String(25))
    rates = db.Column(db.String(255))
    comments = db.Column(db.String(255))


class EODDump(db.Model):
    __tablename__ = 'eod_dump'
    Date = db.Column(db.Date)
    TeamLeader = db.Column(db.String(255))
    Gang = db.Column(db.String(255))
    Work_Type = db.Column(db.String(255))
    Item_Mst_ID = db.Column(db.String(255))
    Item_Description = db.Column(db.String(255))
    Activity = db.Column(db.String(255))
    WeekNumber = db.Column(db.String(255))
    Output_Date_MonthYear = db.Column(db.String(255))
    Qty = db.Column(db.Integer)
    UOM = db.Column(db.String(255))
    Rate = db.Column(DECIMAL(10, 2))
    Total = db.Column(DECIMAL(10, 2))
    Area = db.Column(db.String(255))
    Mst_Item_Rpt_Group1 = db.Column(db.String(255))
    Project_ID = db.Column(db.Integer)
    Project_Name = db.Column(db.String(255))
    Seed = db.Column(db.Integer, primary_key=True)
    Comment = db.Column(db.Text)
    Planning_KPI1 = db.Column(db.String(255))
    Email_ID = db.Column(db.String(255))
    User_Name = db.Column(db.String(255))
    AuditLog = db.Column(db.String(255))
    Work_Period = db.Column(db.String(255))
    Job_Pack_No = db.Column(db.String(255))
    Route = db.Column(db.String(255))
    Work_Category = db.Column(db.String(255))
    Approved_Status = db.Column(db.String(255))
    PMO_Coordinator = db.Column(db.String(255))
    QA_remarks = db.Column(db.Text)
    Span_length = db.Column(db.String(255))
    # Qty_2 = db.Column(db.Integer)
    Taken_To_Revenue = db.Column(db.Boolean)
    Taken_To_Revenue_Date = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        result = {column.name: getattr(self, column.name) for column in self.__table__.columns}
        result['Date'] = self.Date.strftime('%d-%m-%y') if self.Date else None
        return result
        # return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class UserRevenue(db.Model):
    __tablename__ = 'user_revenue'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(255), nullable=False)
    revenue_generating_entity = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'revenue_generating_entity': self.revenue_generating_entity
        }




# Role-Based Access Control Decorator
def role_required(roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if current_user.role not in roles:
                return jsonify({"msg": "Unauthorized access"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper


@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email_id = data.get('email_id')
    phone_no = data.get('phone_no')
    role = data.get('role')
    can_edit = data.get('can_edit', False)

    if not username or not password or not email_id or not role:
        return jsonify({'error': 'Username, password, email_id, and role are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists'}), 400

    if User.query.filter_by(email_id=email_id).first():
        return jsonify({'error': 'Email ID already in use'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, email_id=email_id, phone_no=phone_no, role=role, can_edit=can_edit)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'message': 'Logout successful'}), 200


def send_reset_email(to_email, reset_token):
    
    print(reset_token)
    # Gmail credentials
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    from_email = 'stlautomation123@gmail.com'
    password = 'thyuysdcdonpymsr'

    # Create the email content
    subject = 'Password Reset Request | XX Portal'
    body = f'''
    Hi,

    We received a request to reset your password. Click the link below to reset it:

    http://10.100.130.76:5000/reset_password?token={reset_token}

    If you did not request this, please ignore this email.

    Best regards,
    Team Automation
    '''

    # Create a MIMEText object and set up the email headers
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the Gmail SMTP server and send the email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()

        print('Email sent successfully')
    except Exception as e:
        print(f'Failed to send email: {e}')

# Update the forgot password API to use email_id
@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email_id = data.get('email_id')

    if not email_id:
        return jsonify({'error': 'Email ID is required'}), 400

    user = User.query.filter_by(email_id=email_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a password reset token (you can use JWT or other methods)
    reset_token = create_access_token(identity=email_id, expires_delta=timedelta(hours=1))

    # Send the reset token via email
    send_reset_email(email_id, reset_token)

    return jsonify({'message': 'Password reset link has been sent'}), 200


# Update the reset password API to use email_id
@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')
    print(reset_token)

    if not reset_token or not new_password:
        return jsonify({'error': 'Reset token and new password are required'}), 400

    try:
        # Decode the reset token to get the email_id
        email_id = jwt.decode_token(reset_token)['identity']
    except Exception as e:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.filter_by(email_id=email_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    print("Password reset done")
    db.session.commit()

    return jsonify({'message': 'Password reset successfully'}), 200


@app.route('/api/add_subcontractor_rates', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def add_subcontractor_rates():
    data = request.get_json()
    
    if not isinstance(data, list):
        return jsonify({'error': 'Input data should be a list of entries'}), 400

    results = []
    for entry in data:
        required_fields = ['rate_code', 'work_category', 'rate_type', 'item', 'unit']
        missing_fields = [field for field in required_fields if field not in entry]
        
        if missing_fields:
            results.append({'success': False, 'missing_fields': missing_fields})
            continue

        subcontractor_rate = SubcontractorRate(
            rate_code=entry.get('rate_code'),
            work_category=entry.get('work_category'),
            rate_type=entry.get('rate_type'),
            item=entry.get('item'),
            unit=entry.get('unit'),
            heavy_and_dirty=entry.get('heavy_and_dirty'),
            include_hnd_in_service_price=entry.get('include_hnd_in_service_price'),
            description=entry.get('description'),
            afs=entry.get('afs'),
            bk_comms=entry.get('bk_comms'),
            ccg=entry.get('ccg'),
            jk_comms=entry.get('jk_comms'),
            jdc=entry.get('jdc'),
            jto=entry.get('jto'),
            nola=entry.get('nola'),
            rollo=entry.get('rollo'),
            salcs=entry.get('salcs'),
            upscale=entry.get('upscale'),
            vsl=entry.get('vsl'),
            vus=entry.get('vus')
        )
        
        db.session.add(subcontractor_rate)
        results.append({'success': True, 'data': subcontractor_rate.to_dict()})
    
    db.session.commit()

    return jsonify(results), 201


@app.route('/api/add_user_revenues', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def add_user_revenues():
    data = request.get_json()
    
    if not isinstance(data, list):
        return jsonify({'error': 'Input data should be a list of entries'}), 400

    results = []
    user_revenues = []

    for entry in data:
        user_name = entry.get('user_name')
        revenue_generating_entity = entry.get('revenue_generating_entity')

        if not user_name:
            results.append({'entry': entry, 'success': False, 'error': 'Missing user_name'})
            continue

        if not revenue_generating_entity:
            results.append({'entry': entry, 'success': False, 'error': 'Missing revenue_generating_entity'})
            continue
        
        user_revenue = UserRevenue(user_name=user_name, revenue_generating_entity=revenue_generating_entity)
        user_revenues.append(user_revenue)
        results.append({'entry': entry, 'success': True})

    if user_revenues:
        db.session.bulk_save_objects(user_revenues)
        db.session.commit()

    return jsonify(results), 201 

# API Endpoints
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token, role=user.role, can_edit=user.can_edit), 200
    return jsonify({"msg": "Bad username or password"}), 401


@app.route('/api/data', methods=['GET'])
@jwt_required()
@role_required(['admin', 'editor', 'viewer'])
def get_data():
    filters = request.args.to_dict()

    limit = int(request.args.get('limit', 100))  # Default to 100 rows
    page = int(request.args.get('page', 1))  # Default to page 1

    query = EODDump.query

    for key, value in filters.items():
        if hasattr(EODDump, key):
            query = query.filter(getattr(EODDump, key) == value)

    total_records = query.with_entities(func.count()).scalar()
    data = query.offset((page - 1) * limit).limit(limit).all()

    response = {
        'total_records': total_records,
        'page': page,
        'per_page': limit,
        'data': [item.to_dict() for item in data]
    }

    return jsonify(response)


@app.route('/api/manage_user', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def manage_user():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user:
        user.role = data.get('role', user.role)
        user.can_edit = data.get('can_edit', user.can_edit)
        db.session.commit()
        return jsonify({"success": True, "message": "User updated successfully"})
    return jsonify({"success": False, "message": "User not found"}), 404


@app.route('/api/update_revenue_status', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
def update_revenue_status():
    data = request.json
    user = User.query.filter_by(username=get_jwt_identity()).first()

    if not user.can_edit:
        return jsonify({"success": False, "message": "You don't have edit rights"}), 403

    for item in data['items']:
        eod_item = EODDump.query.get(item['seed'])
        if eod_item:
            eod_item.Taken_To_Revenue = item['Taken_To_Revenue']
            eod_item.Taken_To_Revenue_Date = datetime.now() # Update the date
            log = ActivityLog(user_id=user.id, action=f"Updated Taken_To_Revenue for seed {item['seed']} to {item['Taken_To_Revenue']}")
            db.session.add(log)

    db.session.commit()
    return jsonify({"success": True})




@app.route('/api/get_revenue', methods=['POST'])
@jwt_required()
@role_required(['admin', 'viewer', 'editor'])
def get_revenue():
    user = User.query.filter_by(username=get_jwt_identity()).first()
    print(user)

    data = request.json
    print("Received data:", data)  # Debug statement
    seeds = data.get('Seeds')
    
    if not seeds or not isinstance(seeds, list):
        return jsonify({"success": False, "message": "Seeds parameter is required and must be a list"}), 400
    
    try:
        revenue_results = {}
        for seed in seeds:
            total_revenue = db.session.query(
                db.func.sum(EODDump.Qty * ClientRate.rates)
            ).join(
                ClientRate, EODDump.Item_Mst_ID == ClientRate.rate_code
            ).filter(
                EODDump.Seed == seed
            ).scalar()
            
            revenue_results[seed] = total_revenue if total_revenue is not None else 0
        
        return jsonify({"success": True, "revenue": revenue_results})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500






@app.route('/api/calculate_cost', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
def calculate_cost():
    data = request.json
    if not data or 'seeds' not in data:
        return jsonify({"error": "Invalid input. 'seeds' is required."}), 400

    seeds = data['seeds']
    
    ooh_rates = SubcontractorRate.query.filter_by(rate_code='OOH001').first()
    
    results = []
    for seed in seeds:
        eod_item = EODDump.query.filter_by(Seed=seed).first()
        if not eod_item:
            results.append({"seed": seed, "error": "EOD item not found"})
            continue

        # Get revenue_generating_entity from user_revenue table
        user_rev = UserRevenue.query.filter(func.lower(UserRevenue.user_name) == func.lower(eod_item.User_Name)).first()
        if not user_rev:
            results.append({
                "seed": seed,
                "error": f"User {eod_item.User_Name} not found in UserRevenue table"
            })
            continue
        
        revenue_generating_entity = user_rev.revenue_generating_entity

        # If revenue_generating_entity is "SET", cost is 0
        if revenue_generating_entity.upper() == "SET":
            results.append({
                "seed": seed,
                "date": eod_item.Date.strftime('%Y-%m-%d') if eod_item.Date else None,
                "item_mst_id": eod_item.Item_Mst_ID,
                "qty": eod_item.Qty,
                "username": eod_item.User_Name,
                "revenue_generating_entity": revenue_generating_entity,
                "rate": 0,
                "cost": 0,
                "is_weekend": False,
                "weekend_rate": 0
            })
            continue

        # Get rate from subcontractor_rate table
        subcontractor_rate = SubcontractorRate.query.filter_by(rate_code=eod_item.Item_Mst_ID).first()
        if not subcontractor_rate:
            results.append({
                "seed": seed,
                "error": f"Rate not found for Item_Mst_ID: {eod_item.Item_Mst_ID}"
            })
            continue
        
        # Get the rate for the specific revenue_generating_entity
        rate = getattr(subcontractor_rate, revenue_generating_entity.lower(), None)
        if rate is None:
            results.append({
                "seed": seed,
                "error": f"Rate not found for entity: {revenue_generating_entity}"
            })
            continue
        
        # Calculate base cost
        base_cost = float(eod_item.Qty) * float(rate)
        
        # Check if the date is a weekend
        is_weekend = False
        weekend_rate = 0
        if eod_item.Date:
            if eod_item.Date.weekday() >= 5:  # 5 is Saturday, 6 is Sunday
                is_weekend = True
                weekend_rate = getattr(ooh_rates, revenue_generating_entity.lower(), 0)
                if weekend_rate:
                    base_cost *= (1 + float(weekend_rate) / 100)  # Increase by percentage

        results.append({
            "seed": seed,
            "date": eod_item.Date.strftime('%Y-%m-%d') if eod_item.Date else None,
            "item_mst_id": eod_item.Item_Mst_ID,
            "qty": eod_item.Qty,
            "username": eod_item.User_Name,
            "revenue_generating_entity": revenue_generating_entity,
            "rate": float(rate),
            "cost": base_cost,
            "is_weekend": is_weekend,
            "weekend_rate": float(weekend_rate) if weekend_rate else 0
        })
    
    return jsonify(results)


@app.route('/api/upload', methods=['POST'])
@jwt_required()
@role_required(['admin', 'editor'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        # Read the Excel file into a DataFrame
        df = pd.read_excel(file,skiprows=5,usecols=lambda x: x not in [0])

        # Store DataFrame in the database
        df.to_sql('pn_raw', engine, index=False, if_exists='append')

        return jsonify({'message': 'File uploaded and data stored successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=bcrypt.generate_password_hash('adminpass').decode('utf-8'), role='admin', can_edit=True)
            editor = User(username='editor', password=bcrypt.generate_password_hash('editorpass').decode('utf-8'), role='editor', can_edit=True)
            viewer = User(username='viewer', password=bcrypt.generate_password_hash('viewerpass').decode('utf-8'), role='viewer', can_edit=False)
            db.session.add_all([admin, editor, viewer])
            db.session.commit()
    app.run(host='0.0.0.0', port=5000,debug=True)


