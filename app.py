from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Load datasets
summer_data = pd.read_csv('data/summer.csv', encoding='latin1')  # Example encoding
winter_data = pd.read_csv('data/winter.csv', encoding='latin1')
spring_data = pd.read_csv('data/spring.csv', encoding='latin1')


all_data = pd.concat([summer_data, winter_data, spring_data], keys=['Summer', 'Winter', 'Spring']).reset_index(level=0).rename(columns={"level_0": "Season"})

# Simulated database for users
users = {
    "admin": {"password": generate_password_hash("admin123"), "role": "admin"},
    "user": {"password": generate_password_hash("user123"), "role": "user"}
}

# Authentication route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# Home route
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('plants.html', plants=all_data.to_dict(orient='records'))

# Admin panel for adding users
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('User already exists.', 'warning')
        else:
            users[username] = {"password": generate_password_hash(password), "role": "user"}
            flash('User added successfully.', 'success')
    return render_template('admin.html', users=users)

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
