from flask import Flask, render_template, request
import pandas as pd

app = Flask(__name__)

# Load data
data = pd.concat([
    pd.read_csv('data/summer.csv',encoding='latin1').assign(Category='Summer'),
    pd.read_csv('data/winter.csv',encoding='latin1').assign(Category='Winter'),
    pd.read_csv('data/spring.csv',encoding='latin1').assign(Category='Spring')
])

@app.route('/')
def home():
    categories = data['Category'].unique()
    return render_template('index.html', categories=categories)

@app.route('/plants')
def plants():
    category = request.args.get('category')
    query = request.args.get('query', '').lower()
    filtered_data = data

    if category:
        filtered_data = filtered_data[filtered_data['Category'] == category]
    if query:
        filtered_data = filtered_data[
            filtered_data['Name'].str.lower().str.contains(query)
        ]
    return render_template('plants.html', plants=filtered_data.to_dict(orient='records'))

if __name__ == '__main__':
    app.run(debug=True)
