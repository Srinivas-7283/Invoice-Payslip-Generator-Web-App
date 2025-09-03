import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, create_access_token, create_refresh_token, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
from extensions import db, bcrypt, jwt
from models import User, Employee, Invoice, Payslip, LoginSession, DownloadLog
from utils import roles_required, generate_invoice_pdf, generate_payslip_pdf, generate_meme
import uuid
from decimal import Decimal
import json

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'ucy2zpp2dAZDOaFEW4YnBwzs0TSfPGX4ym6xKyaCKgs')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'z1WekN3f8WIJP0XHBJ-zxss9F8bsAZQuXuv5lLojnHI')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/invoice_db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Simplified for development
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    
    # Create tables and admin user
    with app.app_context():
        db.create_all()
        create_admin_user()
    
    # Routes
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role')
            name = request.form.get('name')
            department = request.form.get('department')
            designation = request.form.get('designation')
            base_salary = request.form.get('base_salary')
            
            # Validation
            if not all([email, password, confirm_password, role, name]):
                flash('Please fill in all required fields', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('register.html')
            
            if role not in ['hr', 'employee', 'client']:
                flash('Invalid role selection', 'error')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('register.html')
            
            # Create user
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(
                email=email,
                password_hash=password_hash,
                role=role,
                is_active=False  # Pending admin approval
            )
            db.session.add(user)
            db.session.commit()
            
            # Create employee record if role is employee or hr
            if role in ['employee', 'hr']:
                employee = Employee(
                    user_id=user.id,
                    name=name,
                    email=email,
                    department=department or '',
                    designation=designation or '',
                    base_salary=Decimal(base_salary) if base_salary else Decimal('0')
                )
                db.session.add(employee)
                db.session.commit()
            
            flash('Registration successful! Please wait for admin approval.', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            
            if not all([email, password, role]):
                flash('Please fill in all fields', 'error')
                return render_template('login.html')
            
            user = User.query.filter_by(email=email, role=role).first()
            
            if user and bcrypt.check_password_hash(user.password_hash, password):
                if not user.is_active and role != 'admin':
                    flash('Your account is pending admin approval', 'warning')
                    return render_template('login.html')
                
                # Create login session for non-admin users
                if role != 'admin':
                    jti = str(uuid.uuid4())
                    login_session = LoginSession(
                        user_id=user.id,
                        jti=jti,
                        token_type='pending',
                        expires_at=datetime.utcnow() + timedelta(minutes=30),
                        user_agent=request.headers.get('User-Agent', ''),
                        ip_address=request.remote_addr,
                        approved=False
                    )
                    db.session.add(login_session)
                    db.session.commit()
                    
                    return redirect(url_for('pending_approval', session_id=login_session.id))
                else:
                    # Direct login for admin
                    access_token = create_access_token(
                        identity=str(user.id),
                        additional_claims={'role': user.role}
                    )
                    refresh_token = create_refresh_token(identity=str(user.id))
                    
                    resp = make_response(redirect(url_for('admin_dashboard')))
                    set_access_cookies(resp, access_token)
                    set_refresh_cookies(resp, refresh_token)
                    return resp
            else:
                flash('Invalid credentials', 'error')
        
        return render_template('login.html')
    
    @app.route('/pending/<int:session_id>')
    def pending_approval(session_id):
        session = LoginSession.query.get_or_404(session_id)
        return render_template('pending.html', session_id=session_id)
    
    @app.route('/issue/<int:session_id>', methods=['POST'])
    def issue_token(session_id):
        session = LoginSession.query.get_or_404(session_id)
        
        if session.approved and not session.revoked:
            user = User.query.get(session.user_id)
            access_token = create_access_token(
                identity=str(user.id),
                additional_claims={'role': user.role}
            )
            refresh_token = create_refresh_token(identity=str(user.id))
            
            # Update session
            session.token_type = 'access'
            db.session.commit()
            
            resp = make_response(jsonify({'status': 'approved', 'redirect': url_for('dashboard')}))
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp
        
        return jsonify({'status': 'pending'}), 202
    
    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        resp = make_response(redirect(url_for('index')))
        unset_jwt_cookies(resp)
        return resp
    
    @app.route('/admin')
    @jwt_required()
    @roles_required('admin')
    def admin_dashboard():
        users = User.query.filter(User.role != 'admin').all()
        pending_logins = LoginSession.query.filter_by(
            approved=False, 
            revoked=False
        ).join(User).add_columns(User.email, User.role).all()
        
        return render_template('admin.html', users=users, pending_logins=pending_logins)
    
    @app.route('/admin/approve/<int:user_id>', methods=['POST'])
    @jwt_required()
    @roles_required('admin')
    def approve_user(user_id):
        user = User.query.get_or_404(user_id)
        user.is_active = True
        db.session.commit()
        flash(f'User {user.email} approved successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    @app.route('/admin/approve-login/<int:session_id>', methods=['POST'])
    @jwt_required()
    @roles_required('admin')
    def approve_login(session_id):
        session = LoginSession.query.get_or_404(session_id)
        session.approved = True
        db.session.commit()
        flash('Login approved successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    @app.route('/dashboard')
    @jwt_required()
    def dashboard():
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        role = get_jwt().get('role')
        
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        
        # Get role-specific data
        stats = {}
        if role in ['hr', 'admin']:
            stats['total_employees'] = Employee.query.count()
            stats['total_invoices'] = Invoice.query.count()
            stats['total_payslips'] = Payslip.query.count()
        elif role == 'employee':
            employee = Employee.query.filter_by(user_id=user_id).first()
            if employee:
                stats['my_payslips'] = Payslip.query.filter_by(employee_id=employee.id).count()
        
        return render_template('dashboard.html', user=user, stats=stats)
    
    @app.route('/invoices', methods=['GET', 'POST'])
    @jwt_required()
    @roles_required('admin', 'hr', 'employee')
    def invoices():
        if request.method == 'POST':
            client_name = request.form.get('client_name')
            due_date = datetime.strptime(request.form.get('due_date'), '%Y-%m-%d').date()
            
            # Parse items
            items = []
            descriptions = request.form.getlist('description[]')
            quantities = request.form.getlist('quantity[]')
            prices = request.form.getlist('price[]')
            taxes = request.form.getlist('tax[]')
            
            subtotal = Decimal('0')
            total_tax = Decimal('0')
            
            for i in range(len(descriptions)):
                if descriptions[i]:
                    qty = Decimal(quantities[i])
                    price = Decimal(prices[i])
                    tax_rate = Decimal(taxes[i]) / 100
                    
                    line_total = qty * price
                    line_tax = line_total * tax_rate
                    
                    items.append({
                        'description': descriptions[i],
                        'quantity': float(qty),
                        'price': float(price),
                        'tax_rate': float(tax_rate * 100),
                        'total': float(line_total)
                    })
                    
                    subtotal += line_total
                    total_tax += line_tax
            
            total = subtotal + total_tax
            
            # Generate invoice number
            invoice_count = Invoice.query.count() + 1
            invoice_number = f"INV-{datetime.now().year}-{invoice_count:04d}"
            
            invoice = Invoice(
                number=invoice_number,
                client_name=client_name,
                items_json=items,
                subtotal=subtotal,
                tax=total_tax,
                total=total,
                due_date=due_date,
                created_by=int(get_jwt_identity())
            )
            
            db.session.add(invoice)
            db.session.commit()
            
            flash('Invoice created successfully', 'success')
            return redirect(url_for('invoices'))
        
        invoices = Invoice.query.all()
        return render_template('invoices.html', invoices=invoices)
    
    @app.route('/invoices/pdf/<int:invoice_id>')
    @jwt_required()
    @roles_required('admin', 'hr', 'employee', 'client')
    def invoice_pdf(invoice_id):
        invoice = Invoice.query.get_or_404(invoice_id)
        
        # Log download
        log = DownloadLog(
            user_id=int(get_jwt_identity()),
            doc_type='invoice',
            doc_id=invoice_id
        )
        db.session.add(log)
        db.session.commit()
        
        return generate_invoice_pdf(invoice)
    
    @app.route('/payslips', methods=['GET', 'POST'])
    @jwt_required()
    @roles_required('admin', 'hr', 'employee')
    def payslips():
        user_id = int(get_jwt_identity())
        role = get_jwt().get('role')
        
        if request.method == 'POST' and role in ['admin', 'hr']:
            employee_id = request.form.get('employee_id')
            month = int(request.form.get('month'))
            year = int(request.form.get('year'))
            
            # Parse earnings
            earnings = []
            earning_names = request.form.getlist('earning_name[]')
            earning_amounts = request.form.getlist('earning_amount[]')
            
            total_earnings = Decimal('0')
            for i in range(len(earning_names)):
                if earning_names[i]:
                    amount = Decimal(earning_amounts[i])
                    earnings.append({
                        'name': earning_names[i],
                        'amount': float(amount)
                    })
                    total_earnings += amount
            
            # Parse deductions
            deductions = []
            deduction_names = request.form.getlist('deduction_name[]')
            deduction_amounts = request.form.getlist('deduction_amount[]')
            
            total_deductions = Decimal('0')
            for i in range(len(deduction_names)):
                if deduction_names[i]:
                    amount = Decimal(deduction_amounts[i])
                    deductions.append({
                        'name': deduction_names[i],
                        'amount': float(amount)
                    })
                    total_deductions += amount
            
            net_pay = total_earnings - total_deductions
            
            payslip = Payslip(
                employee_id=employee_id,
                month=month,
                year=year,
                earnings_json=earnings,
                deductions_json=deductions,
                net_pay=net_pay
            )
            
            db.session.add(payslip)
            db.session.commit()
            
            flash('Payslip created successfully', 'success')
            return redirect(url_for('payslips'))
        
        # Get payslips based on role
        if role == 'employee':
            employee = Employee.query.filter_by(user_id=user_id).first()
            payslips = Payslip.query.filter_by(employee_id=employee.id).all() if employee else []
        else:
            payslips = Payslip.query.all()
        
        employees = Employee.query.all() if role in ['admin', 'hr'] else []
        
        return render_template('payslips.html', payslips=payslips, employees=employees)
    
    @app.route('/payslips/pdf/<int:payslip_id>')
    @jwt_required()
    @roles_required('admin', 'hr', 'employee')
    def payslip_pdf(payslip_id):
        payslip = Payslip.query.get_or_404(payslip_id)
        
        # Check access for employees
        role = get_jwt().get('role')
        if role == 'employee':
            employee = Employee.query.filter_by(user_id=int(get_jwt_identity())).first()
            if not employee or payslip.employee_id != employee.id:
                flash('Access denied', 'error')
                return redirect(url_for('payslips'))
        
        # Log download
        log = DownloadLog(
            user_id=int(get_jwt_identity()),
            doc_type='payslip',
            doc_id=payslip_id
        )
        db.session.add(log)
        db.session.commit()
        
        return generate_payslip_pdf(payslip)
    
    @app.route('/memes/generate')
    def generate_money_meme():
        net_pay = request.args.get('net_pay', '0')
        return generate_meme(net_pay)
    
    return app

def create_admin_user():
    """Create the hardcoded admin user if it doesn't exist"""
    admin_email = 'srinivas72@gmail.com'
    admin = User.query.filter_by(email=admin_email).first()
    
    if not admin:
        password_hash = bcrypt.generate_password_hash('srinivas72').decode('utf-8')
        admin = User(
            email=admin_email,
            password_hash=password_hash,
            role='admin',
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user created: {admin_email}")

if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()
    
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
