import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ucy2zpp2dAZDOaFEW4YnBwzs0TSfPGX4ym6xKyaCKgs'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'z1WekN3f8WIJP0XHBJ-zxss9F8bsAZQuXuv5lLojnHI'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:postgres@localhost:5432/invoice_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
