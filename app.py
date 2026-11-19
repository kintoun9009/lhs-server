
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Servidor Python funcionando!"

@app.route("/player")
def player():
    return "Rota do player funcionando!"

