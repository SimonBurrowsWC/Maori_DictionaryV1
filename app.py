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


@app.route('/dictionary')
def render_dictionary():  # put application's code here
    con = create_connection(DATABASE)
    query = "SELECT id, Maori_Word, English_Word, Definition, Level, catagory FROM words"
    cur = con.cursor()
    cur.execute(query)
    word_list = cur.fetchall()
    con.close()
    return render_template("Dictionary.html", words=word_list)


if __name__ == '__main__':
    app.run()
