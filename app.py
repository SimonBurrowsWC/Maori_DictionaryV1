from flask import Flask, render_template
import sqlite3
from sqlite3 import Error

DATABASE = "dictionary.db"

app = Flask(__name__)


def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


@app.route('/')
def render_home():  # put application's code here
    return render_template("home.html")


@app.route('/dictionary/sort_by:<sort_method>')
def render_dictionary(sort_method):  # put application's code here
    con = create_connection(DATABASE)
    query = f"SELECT * FROM words ORDER BY {sort_method} "
    cur = con.cursor()
    cur.execute(query, )
    word_list = cur.fetchall()
    con.close()
    if sort_method == "id":
        sort_method = "Default"
    sort_method = sort_method.replace("_", " ")
    return render_template("Dictionary.html", words=word_list, sort=sort_method)


@app.route('/login')
def render_login():  # put application's code here
    return render_template("login.html")


@app.route('/signup')
def render_signup():  # put application's code here
    return render_template("signup.html")


if __name__ == '__main__':
    app.run()
