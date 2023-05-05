from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "dictionary.db"

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "FGdfhgskgfbHDgvOIYgfibg9i9ugh"


def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


def is_admin():
    if is_logged_in():
        con = create_connection(DATABASE)
        query = f"SELECT admin FROM user"
        cur = con.cursor()
        cur.execute(query)
        user = cur.fetchone()
        admin = user[0]
        con.close()
        return admin
    else:
        return False


def form_get(x):
    return request.form.get(x)


@app.route('/')
def render_home():  # put application's code here
    if is_logged_in():
        fname = "SELECT fname FROM user"
    return render_template("home.html", logged_in=is_logged_in(), adminbool=is_admin())


@app.route('/dictionary/filter_by:<category>')
def render_dictionary(category):  # put application's code here
    con = create_connection(DATABASE)
    query = f"SELECT * FROM words WHERE category=?"
    cur = con.cursor()
    cur.execute(query, (category,))
    word_list = cur.fetchall()
    con.close()

    con = create_connection(DATABASE)
    query = "SELECT * FROM category"
    cur = con.cursor()
    cur.execute(query, )
    category_list = cur.fetchall()
    current_category = category_list[int(category) - 1][1]
    con.close()

    return render_template("/Dictionary.html", words=word_list, filter=current_category, logged_in=is_logged_in(),
                           categories=category_list, adminbool=is_admin())


@app.route('/login', methods=['POST', 'GET'])
def render_login():  # put application's code here
    if is_logged_in():
        return redirect('/')
    print("Loging in")
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        print(email)
        query = "SELECT id, fname, password FROM user WHERE email = ?"
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()
        print(user_data)
        # if given the email is not in the database this will raise an error
        # would be better to find out how to see if the query will return an empty result
        try:
            user_id = user_data[0]
            firstname = user_data[1]
            db_password = user_data[2]
        except IndexError:
            return redirect("/login?error=Invalid+username+or+password")

            # check if the pasword is invalid for the email adress 10:30#

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['user_id'] = user_id
        session['firstname'] = firstname

        print(session)
        return redirect('/')
    return render_template("login.html", logged_in=is_logged_in())


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():  # put application's code here
    if is_logged_in():
        return redirect('/menu/1')
    if request.method == 'POST':
        print(request.form)
        fname = request.form.get('fname').title().strip()
        lname = request.form.get('lname').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:
            return redirect("\signup?error=Passwords+do+not+match")

        if len(password) < 8:
            return redirect("/signup?error=Password+must+be+at+least+8+characters")

        hashed_password = bcrypt.generate_password_hash(password)
        con = create_connection(DATABASE)
        query = "INSERT INTO user (fname, lname, email, password) VALUES (?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (fname, lname, email, hashed_password))
        except sqlite3.IntegrityError:
            con.close()
            return redirect("\signup?error=Email+is+already+in+use")

        con.commit()
        con.close()

        return redirect("\login")

    return render_template("signup.html", logged_in=is_logged_in())


@app.route('/logout')
def render_logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=see+you+next+time!')


@app.route('/admin')
def render_admin():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    # Fetch the categories
    query = "SELECT * FROM category"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    query = "SELECT * FROM words"
    cur.execute(query)
    word_list = cur.fetchall()
    con.close()
    return render_template("admin.html", words = word_list, categories=category_list, logged_in=is_logged_in(), adminbool=is_admin())


@app.route('/add_category', methods =['POST'])
def render_add_category():
    if request.method == "POST":
        print(request.form)
        cat_name = request.form.get('name').lower().strip()
        print(cat_name)
        con = create_connection(DATABASE)
        query = "INSERT INTO category ('category_name') VALUES (?)"
        cur = con.cursor()
        cur.execute(query, (cat_name,))
        con.commit()
        con.close()
        return redirect('/admin')


@app.route('/delete_category', methods =['POST'])
def render_delete_category():
    if not is_admin():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        category = request.form.get('cat_id')
        print(category)
        category = category.split(", ")
        cat_id = category[0]
        cat_name = category[1]
        return render_template("delete_confirm.html", cat_id=cat_id, cat_name=cat_name, type="category")
    return redirect("/admin")


@app.route('/delete_category_confirm/<cat_id>')
def delete_category_confirm(cat_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "DELETE FROM category WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (cat_id, ))
    con.commit()
    con.close()
    return redirect("/admin")


@app.route('/add_word', methods =['POST'])
def render_add_word():
    if request.method == "POST":
        word_info = request.form
        Maori_Word = request.form.get('Maori').title().strip()
        English_Word = request.form.get('English').title().strip()
        Definition = request.form.get('Definition').lower().strip()
        Level = request.form.get('Level').lower().strip()
        category = request.form.get('cat_id').lower().strip()[1]
        image = request.form.get('Image').strip()
        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO words (Maori_Word, English_Word, Definition, Level, category, image) VALUES(?, ?, ?, ?, ?, ?)"
        cur.execute(query, (Maori_Word, English_Word, Definition, Level, category, image))
        con.commit()
        con.close()
        return redirect('/admin')


@app.route('/delete_word', methods =['POST'])
def render_delete_word():
    if not is_admin():
        return redirect('/?message=Need+to+be+an+admin.')
    if request.method == "POST":
        word = request.form.get('word_id')
        print(word)
        word = word.split(", ")
        word_id = word[0]
        word_name = word[1]
        return render_template("delete_confirm.html", word_id=word_id, word_name=word_name, type="word")
    return redirect("/admin")


if __name__ == '__main__':
    app.run()
