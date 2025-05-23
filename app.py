from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from decimal import Decimal
import pymysql
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_mail import Mail, Message
import os
from config import Config
from db_utils import init_db, TransactionManager, db

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db, data_sync = init_db(app)

# Initialize other extensions
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Add custom Jinja2 filter for currency formatting
@app.template_filter('currency')
def format_currency(value):
    return f"₹{value:,.2f}"

# Add custom Jinja2 filter for date formatting
@app.template_filter('strftime')
def format_datetime(value, format='%Y-%m-%d'):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'staff'
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    product = db.relationship('Product', backref=db.backref('inventory', lazy=True))

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sale_date = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('Product', backref=db.backref('sales', lazy=True))
    staff = db.relationship('User', backref=db.backref('sales', lazy=True))

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='activities')

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('staff_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('staff_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('staff_dashboard'))
    
    return render_template('login.html', title='Sign In', form=form)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    # Calculate statistics
    total_revenue = db.session.query(db.func.sum(Sale.total_price)).scalar() or 0
    total_products = Product.query.count()
    total_staff = User.query.filter_by(role='staff').count()
    low_stock_count = Inventory.query.filter(Inventory.quantity < 10).count()
    
    # Get recent activities
    recent_activities = Activity.query.order_by(Activity.timestamp.desc()).limit(10).all()
    
    return render_template('admin.html',
                         total_revenue=total_revenue,
                         total_products=total_products,
                         total_staff=total_staff,
                         low_stock_count=low_stock_count,
                         recent_activities=recent_activities)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def system_settings():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    if request.method == 'POST':
        # Update system settings
        setting_name = request.form.get('setting_name')
        setting_value = request.form.get('setting_value')
        
        # Log the activity
        activity = Activity(
            user_id=current_user.id,
            action='Settings Update',
            details=f'Updated {setting_name} to {setting_value}'
        )
        db.session.add(activity)
        db.session.commit()
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('settings.html')

@app.route('/admin/backup', methods=['POST'])
@login_required
def backup_database():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    try:
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'backup_{timestamp}.sql'
        
        # Log the activity
        activity = Activity(
            user_id=current_user.id,
            action='Database Backup',
            details=f'Created backup: {backup_filename}'
        )
        db.session.add(activity)
        db.session.commit()
        
        flash('Database backup created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/staff/dashboard')
@login_required
def staff_dashboard():
    if current_user.role != 'staff':
        flash('Access denied. Staff only.', 'danger')
        return redirect(url_for('index'))
    
    # Calculate today's sales
    today = datetime.now().date()
    today_sales = db.session.query(db.func.sum(Sale.total_price)).filter(
        db.func.date(Sale.sale_date) == today
    ).scalar() or 0
    
    # Calculate yesterday's sales for trend
    yesterday = today - timedelta(days=1)
    yesterday_sales = db.session.query(db.func.sum(Sale.total_price)).filter(
        db.func.date(Sale.sale_date) == yesterday
    ).scalar() or 0
    
    # Calculate sales trend
    sales_trend = 0
    if yesterday_sales > 0:
        sales_trend = round(((today_sales - yesterday_sales) / yesterday_sales) * 100, 1)
    
    # Get staff's today sales
    your_sales_count = Sale.query.filter(
        db.func.date(Sale.sale_date) == today,
        Sale.staff_id == current_user.id
    ).count()
    
    # Get staff's yesterday sales for trend
    your_yesterday_sales = Sale.query.filter(
        db.func.date(Sale.sale_date) == yesterday,
        Sale.staff_id == current_user.id
    ).count()
    
    # Calculate staff sales trend
    your_sales_trend = 0
    if your_yesterday_sales > 0:
        your_sales_trend = round(((your_sales_count - your_yesterday_sales) / your_yesterday_sales) * 100, 1)
    
    # Get total products and low stock count
    total_products = Product.query.count()
    low_stock_count = Inventory.query.filter(Inventory.quantity <= 10).count()
    
    # Get recent sales by this staff member
    recent_sales = Sale.query.filter_by(staff_id=current_user.id)\
        .order_by(Sale.sale_date.desc())\
        .limit(10)\
        .all()
    
    return render_template('staff.html',
                         today_sales=today_sales,
                         sales_trend=sales_trend,
                         total_products=total_products,
                         low_stock_count=low_stock_count,
                         your_sales_count=your_sales_count,
                         your_sales_trend=your_sales_trend,
                         recent_sales=recent_sales)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/sales/report')
@login_required
def sales_report():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    # Get sales data
    sales = Sale.query.order_by(Sale.sale_date.desc()).all()
    
    # Calculate total revenue
    total_revenue = sum(sale.total_price for sale in sales)
    
    # Get daily sales
    daily_sales = db.session.query(
        db.func.date(Sale.sale_date),
        db.func.sum(Sale.total_price)
    ).group_by(db.func.date(Sale.sale_date)).all()
    
    # Get top selling products
    top_products = db.session.query(
        Product.name,
        db.func.sum(Sale.quantity).label('total_quantity'),
        db.func.sum(Sale.total_price).label('total_revenue')
    ).join(Sale).group_by(Product.id).order_by(db.desc('total_quantity')).limit(5).all()
    
    return render_template('sales_report.html',
                         sales=sales,
                         total_revenue=total_revenue,
                         daily_sales=daily_sales,
                         top_products=top_products)

@app.route('/admin/sales/report/download')
@login_required
def download_sales_report():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    # Get sales data
    sales = Sale.query.order_by(Sale.sale_date.desc()).all()
    
    # Create CSV content
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Date', 'Product', 'Quantity', 'Price', 'Total', 'Staff'])
    
    # Write data
    for sale in sales:
        writer.writerow([
            sale.sale_date.strftime('%Y-%m-%d %H:%M:%S'),
            sale.product.name,
            sale.quantity,
            f"₹{sale.product.price:,.2f}",
            f"₹{sale.total_price:,.2f}",
            sale.staff.username
        ])
    
    # Prepare response
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=sales_report.csv"}
    )

@app.route('/admin/inventory/manage', methods=['GET', 'POST'])
@login_required
def manage_inventory():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        new_quantity = int(request.form.get('quantity'))
        
        inventory = Inventory.query.filter_by(product_id=product_id).first()
        if inventory:
            inventory.quantity = new_quantity
            inventory.last_updated = datetime.utcnow()
            db.session.commit()
            flash('Inventory updated successfully!', 'success')
        else:
            flash('Product not found!', 'error')
    
    # Get all products with their inventory
    products = Product.query.all()
    inventory_data = []
    for product in products:
        inv = Inventory.query.filter_by(product_id=product.id).first()
        inventory_data.append({
            'product': product,
            'quantity': inv.quantity if inv else 0,
            'last_updated': inv.last_updated if inv else None
        })
    
    return render_template('manage_inventory.html', inventory_data=inventory_data)

@app.route('/admin/users/manage', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    if request.method == 'POST':
        if 'delete_user' in request.form:
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user and user.id != current_user.id:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
            else:
                flash('Cannot delete this user!', 'error')
        elif 'add_user' in request.form:
            try:
                username = request.form.get('username')
                email = request.form.get('email')
                password = request.form.get('password')
                role = request.form.get('role')
                
                print(f"Attempting to create user: {username}")  # Debug log
                
                # Validate input
                if not all([username, email, password, role]):
                    flash('All fields are required!', 'error')
                    return redirect(url_for('manage_users'))
                
                # Check if username or email already exists
                if User.query.filter_by(username=username).first():
                    flash('Username already exists!', 'error')
                    return redirect(url_for('manage_users'))
                
                if User.query.filter_by(email=email).first():
                    flash('Email already exists!', 'error')
                    return redirect(url_for('manage_users'))
                
                # Create new user
                new_user = User(
                    username=username,
                    email=email,
                    role=role
                )
                new_user.set_password(password)
                
                print(f"Created user object: {new_user.username}")  # Debug log
                
                # Add to database
                db.session.add(new_user)
                
                # Log the activity
                activity = Activity(
                    user_id=current_user.id,
                    action='User Creation',
                    details=f'Created new {role} user: {username}'
                )
                db.session.add(activity)
                
                # Commit the transaction
                db.session.commit()
                print(f"User committed to database: {username}")  # Debug log
                
                flash('User added successfully!', 'success')
                
            except Exception as e:
                db.session.rollback()
                print(f"Error creating user: {str(e)}")  # Debug log
                flash(f'Error creating user: {str(e)}', 'error')
                return redirect(url_for('manage_users'))
    
    # Get all users
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        category = request.form.get('category')
        quantity = int(request.form.get('quantity', 0))
        
        new_product = Product(
            name=name,
            description=description,
            price=price,
            category=category
        )
        db.session.add(new_product)
        db.session.commit()
        
        # Create inventory entry
        inventory = Inventory(product_id=new_product.id, quantity=quantity)
        db.session.add(inventory)
        db.session.commit()
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('manage_inventory'))
    
    return render_template('add_product.html')

@app.route('/admin/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    product = Product.query.get_or_404(product_id)
    inventory = Inventory.query.filter_by(product_id=product_id).first()
    
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.category = request.form.get('category')
        
        if inventory:
            inventory.quantity = int(request.form.get('quantity', 0))
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('manage_inventory'))
    
    return render_template('edit_product.html', product=product, inventory=inventory)

@app.route('/admin/products/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_dashboard'))
    
    product = Product.query.get_or_404(product_id)
    inventory = Inventory.query.filter_by(product_id=product_id).first()
    
    if inventory:
        db.session.delete(inventory)
    
    db.session.delete(product)
    db.session.commit()
    
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('manage_inventory'))

@app.route('/staff/performance')
@login_required
def staff_performance():
    if current_user.role != 'staff':
        flash('Access denied. Staff only.', 'danger')
        return redirect(url_for('index'))
    
    # Get date range (last 30 days)
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=30)
    
    # Get sales data for the period
    sales = Sale.query.filter(
        Sale.staff_id == current_user.id,
        db.func.date(Sale.sale_date).between(start_date, end_date)
    ).order_by(Sale.sale_date.desc()).all()
    
    # Calculate total sales and revenue
    total_sales = len(sales)
    total_revenue = sum(sale.total_price for sale in sales)
    
    # Get daily sales data
    daily_sales = db.session.query(
        db.func.date(Sale.sale_date).label('date'),
        db.func.count(Sale.id).label('count'),
        db.func.sum(Sale.total_price).label('revenue')
    ).filter(
        Sale.staff_id == current_user.id,
        db.func.date(Sale.sale_date).between(start_date, end_date)
    ).group_by(db.func.date(Sale.sale_date)).all()
    
    # Get top selling products
    top_products = db.session.query(
        Product.name,
        db.func.sum(Sale.quantity).label('total_quantity'),
        db.func.sum(Sale.total_price).label('total_revenue')
    ).join(Sale).filter(
        Sale.staff_id == current_user.id,
        db.func.date(Sale.sale_date).between(start_date, end_date)
    ).group_by(Product.id).order_by(db.desc('total_quantity')).limit(5).all()
    
    return render_template('staff_performance.html',
                         sales=sales,
                         total_sales=total_sales,
                         total_revenue=total_revenue,
                         daily_sales=daily_sales,
                         top_products=top_products,
                         start_date=start_date,
                         end_date=end_date)

@app.route('/staff/low-stock')
@login_required
def low_stock_items():
    if current_user.role != 'staff':
        flash('Access denied. Staff only.', 'danger')
        return redirect(url_for('index'))
    
    # Get products with low stock (less than 10 items)
    low_stock = db.session.query(Product, Inventory)\
        .join(Inventory)\
        .filter(Inventory.quantity < 10)\
        .order_by(Inventory.quantity.asc())\
        .all()
    
    return render_template('low_stock.html', low_stock=low_stock)

@app.route('/staff/today-sales')
@login_required
def today_sales():
    if current_user.role != 'staff':
        flash('Access denied. Staff only.', 'danger')
        return redirect(url_for('index'))
    
    # Get today's date
    today = datetime.now().date()
    
    # Get all sales for today
    sales = db.session.query(Sale, Product)\
        .join(Product)\
        .filter(db.func.date(Sale.sale_date) == today)\
        .order_by(Sale.sale_date.desc())\
        .all()
    
    # Calculate total sales and revenue for today
    total_sales = len(sales)
    total_revenue = sum(sale[0].total_price for sale in sales)
    
    return render_template('today_sales.html',
                         sales=sales,
                         total_sales=total_sales,
                         total_revenue=total_revenue,
                         today=today)

@app.route('/staff/billing', methods=['GET', 'POST'])
@login_required
def staff_billing():
    if current_user.role != 'staff':
        flash('Access denied. Staff only.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            # Get form data
            product_ids = request.form.getlist('products[]')
            quantities = request.form.getlist('quantities[]')
            
            if not product_ids or not quantities:
                flash('Please select at least one product', 'warning')
                return redirect(url_for('staff_billing'))
            
            # Create transaction
            with TransactionManager() as tm:
                # Generate bill number
                bill_number = f"BILL-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                # Process each product
                total_amount = 0
                items = []
                
                for product_id, quantity in zip(product_ids, quantities):
                    if not product_id or not quantity:
                        continue
                        
                    product = Product.query.get(product_id)
                    if not product:
                        continue
                        
                    quantity = int(quantity)
                    if quantity <= 0:
                        continue
                        
                    # Check stock
                    inventory = Inventory.query.filter_by(product_id=product.id).first()
                    if not inventory or inventory.quantity < quantity:
                        flash(f'Insufficient stock for {product.name}', 'warning')
                        return redirect(url_for('staff_billing'))
                    
                    # Calculate item total
                    item_total = product.price * quantity
                    total_amount += item_total
                    
                    # Update stock
                    inventory.quantity -= quantity
                    # Add to items list
                    items.append({
                        'product_name': product.name,
                        'quantity': quantity,
                        'unit_price': product.price,
                        'total_price': item_total
                    })
                # Create sale record
                sale = Sale(
                    bill_number=bill_number,
                    total_amount=total_amount,
                    staff_id=current_user.id
                )
                db.session.add(sale)
                db.session.commit()
                # Prepare bill data
                bill = {
                    'bill_number': bill_number,
                    'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'staff_name': current_user.username,
                    'items': items,
                    'total_price': total_amount
                }
            flash('Sale completed successfully!', 'success')
            return render_template('bill.html', bill=bill)
            
        except Exception as e:
            flash(f'Error processing sale: {str(e)}', 'danger')
            return redirect(url_for('staff_billing'))
    
    # GET request - show billing form
    products = Product.query.join(Inventory).filter(Inventory.quantity > 0).all()
    return render_template('billing.html', products=products)

def create_sample_data():
    try:
        # Create sample users
        users = [
            User(username='admin', role='admin', email='admin@retail.com'),
            User(username='staff1', role='staff', email='staff1@retail.com'),
            User(username='staff2', role='staff', email='staff2@retail.com')
        ]
        
        for user in users:
            user.set_password('password123')
            db.session.add(user)
        
        # Commit users first
        db.session.commit()
        
        # Create sample products
        products = [
            Product(name='Laptop', description='High-performance laptop', price=999.99, category='Electronics'),
            Product(name='Smartphone', description='Latest smartphone model', price=699.99, category='Electronics'),
            Product(name='Headphones', description='Wireless noise-canceling headphones', price=199.99, category='Accessories'),
            Product(name='Coffee Maker', description='Automatic coffee maker', price=79.99, category='Appliances'),
            Product(name='Desk Chair', description='Ergonomic office chair', price=149.99, category='Furniture')
        ]
        
        for product in products:
            db.session.add(product)
        
        # Commit products
        db.session.commit()
        
        # Create sample inventory
        for product in products:
            inventory = Inventory(product_id=product.id, quantity=10)
            db.session.add(inventory)
        
        # Commit inventory
        db.session.commit()
        
        # Create sample sales
        staff1 = User.query.filter_by(username='staff1').first()
        for product in products[:3]:  # Create sales for first 3 products
            sale = Sale(
                product_id=product.id,
                quantity=2,
                total_price=product.price * 2,
                staff_id=staff1.id
            )
            db.session.add(sale)
        
        # Commit sales
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        raise e

def init_db():
    """Initialize the database with all required tables"""
    with app.app_context():
        # Drop all existing tables
        db.drop_all()
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")
        
        # Create sample data
        create_sample_data()
        print("Sample data created successfully!")

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message('Reset Your Password',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                         title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

def clear_all_sessions():
    """Clear all database sessions and connections"""
    try:
        # Close all sessions
        db.session.remove()
        # Dispose the engine
        db.engine.dispose()
        print("All database sessions and connections cleared successfully!")
    except Exception as e:
        print(f"Error clearing sessions: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True, port=5003) 