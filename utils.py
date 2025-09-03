from functools import wraps
from flask import flash, redirect, url_for, make_response, render_template
from flask_jwt_extended import get_jwt
from io import BytesIO
from xhtml2pdf import pisa
from PIL import Image, ImageDraw, ImageFont
import random

def roles_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_role = get_jwt().get('role')
            if current_user_role not in required_roles:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_invoice_pdf(invoice):
    """Generate PDF for invoice"""
    html_content = render_template('invoice_pdf.html', invoice=invoice)
    
    # Create PDF
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html_content.encode("UTF-8")), result)
    
    if not pdf.err:
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=invoice_{invoice.number}.pdf'
        return response
    
    flash('Error generating PDF', 'error')
    return redirect(url_for('invoices'))

def generate_payslip_pdf(payslip):
    """Generate PDF for payslip"""
    html_content = render_template('payslip_pdf.html', payslip=payslip)
    
    # Create PDF
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html_content.encode("UTF-8")), result)
    
    if not pdf.err:
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=payslip_{payslip.employee.name}_{payslip.month}_{payslip.year}.pdf'
        return response
    
    flash('Error generating PDF', 'error')
    return redirect(url_for('payslips'))

def generate_meme(net_pay):
    """Generate a money-related meme"""
    quotes = [
        "Money talks, but mine says goodbye!",
        "I'm not broke, I'm pre-rich!",
        "My bank account is like an onion - it makes me cry!",
        "I have enough money to last me the rest of my life... unless I buy something!",
        "Money can't buy happiness, but it can buy coffee!",
        "I'm not cheap, I'm economically selective!",
        "My paycheck and I have a lot in common - we both disappear quickly!",
        "I don't have a spending problem, I have an earning problem!"
    ]
    
    # Create image
    img = Image.new('RGB', (600, 400), color='lightblue')
    draw = ImageDraw.Draw(img)
    
    # Try to use a system font, fallback to default
    try:
        font = ImageFont.truetype("arial.ttf", 24)
        small_font = ImageFont.truetype("arial.ttf", 18)
    except:
        font = ImageFont.load_default()
        small_font = ImageFont.load_default()
    
    # Add text
    quote = random.choice(quotes)
    draw.text((50, 150), quote, fill='black', font=font)
    draw.text((50, 300), f"Net Pay: ${net_pay}", fill='green', font=small_font)
    
    # Save to bytes
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    response = make_response(img_bytes.getvalue())
    response.headers['Content-Type'] = 'image/png'
    return response