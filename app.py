# Imports all the required modules #
try:
    from flask import Flask, render_template, redirect, request, session
    import sqlite3
    from sqlite3 import Error
    from flask_bcrypt import Bcrypt
except ImportError:
    import os
    os.system("static/downloadModules.bat")
    from flask import Flask, render_template, redirect, request, session
    import sqlite3
    from sqlite3 import Error
    from flask_bcrypt import Bcrypt

# Sets the name of the database file #
DATABASE = "dictionary.db"

# Variable declaration #
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "FGdfhgskgfbHDgvOIYgfibg9i9ugh"


# Creates a connection to the database so data can be pulled and pushed #
def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


# Checks if the user is logged in by checking if an email is available in the current section#
def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


# Checks if the user is logged in then sees if the user has admin privileges #
def is_admin():
    if is_logged_in():
        con = create_connection(DATABASE)
        query = "SELECT admin FROM user WHERE id = ?"
        cur = con.cursor()
        cur.execute(query, (session['user_id'], ))
        user = cur.fetchone()
        admin = user[0]
        con.close()
        return admin
    else:
        return False


# Loads the home page with the users first name #
@app.route('/')
def render_home():  # put application's code here
    firstname = ''
    if is_logged_in():
        firstname += session['firstname']
    return render_template("home.html", logged_in=is_logged_in(), adminbool=is_admin(), First_Name=firstname)


# Renders the dictionary sorted by the category that the user selects and if the user is an admin it will also display
# the last editor #
@app.route('/dictionary/filter_by:<category>')
def render_dictionary(category):  # put application's code here
    con = create_connection(DATABASE)
    query = "SELECT * FROM words WHERE category=?"
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

    return render_template("Dictionary.html", words=word_list, filter=current_category, logged_in=is_logged_in(),
                           categories=category_list, adminbool=is_admin())


# A page for logging the user in and if the user is logged in it will redirect them to the home page #
@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/')
    print("Loging in")
    if request.method == "POST":
        # Checks if the email is in the database #
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        query = "SELECT id, fname, password FROM user WHERE email = ?"
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()

        if user_data is None:
            return redirect("/login?error=Invalid+email")
        try:
            user_id = user_data[0]
            firstname = user_data[1]
            db_password = user_data[2]
        except IndexError:
            return redirect("/login?error=Invalid+username+or+password")

            # check if the password matches the password for the specific email address#
        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['user_id'] = user_id
        session['firstname'] = firstname

        print(session)
        # Returns the user to the home page #
        return redirect('/')
    return render_template("login.html", logged_in=is_logged_in())


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    # If the user is logged in it sends them to the home page #
    if is_logged_in():
        return redirect('/')
    if request.method == 'POST':
        # Gets the information from the html form and sets them to the following variables #
        fname = request.form.get('fname').title().strip()
        lname = request.form.get('lname').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        # Checks if the passwords match #
        if password != password2:
            return redirect("\signup?error=Passwords+do+not+match")

        # Checks if the password is longer than 8 characters #
        if len(password) < 8:
            return redirect("/signup?error=Password+must+be+at+least+8+characters")
        # Hashes the password then tries to insert into the database and returns an error if it is already in use #
        hashed_password = bcrypt.generate_password_hash(password)
        con = create_connection(DATABASE)
        query = "INSERT INTO user (fname, lname, email, password, admin) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (fname, lname, email, hashed_password, 0))
        except sqlite3.IntegrityError:
            con.close()
            return redirect("\signup?error=Email+is+already+in+use")

        con.commit()
        con.close()

        return redirect("\login")

    return render_template("signup.html", logged_in=is_logged_in())


# Logs out the user #
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
    # Fetch the categories #
    query = "SELECT * FROM category"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    # Fetch the words #
    query = "SELECT * FROM words"
    cur.execute(query)
    word_list = cur.fetchall()
    con.close()
    return render_template("admin.html", words=word_list, categories=category_list, logged_in=is_logged_in(),
                           adminbool=is_admin())


# Adds a category with the name from the HTML form #
@app.route('/add_category', methods=['POST', 'GET'])
def render_add_category():
    if request.method == "POST":
        cat_name = request.form.get('name').lower().strip()
        con = create_connection(DATABASE)
        query = "INSERT INTO category ('category_name') VALUES (?)"
        cur = con.cursor()
        cur.execute(query, (cat_name,))
        con.commit()
        con.close()
        return redirect('/admin')


# If the user is an admin it will delete the category that the user has selected #
@app.route('/delete_category', methods=['POST'])
def render_delete_category():
    if not is_admin():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        category = request.form.get('cat_id')
        category = category.split(", ")
        cat_id = category[0]
        cat_name = category[1]
        return render_template("delete_confirm.html", cat_id=cat_id, cat_name=cat_name, type="category")
    return redirect("/admin")


# Deletes the category that the user has selected if they confirmed it #
@app.route('/delete_category_confirm/<cat_id>')
def delete_category_confirm(cat_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "DELETE FROM category WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (cat_id,))
    con.commit()
    con.close()
    return redirect("/admin")


# Adds a word to the words table with the user that has done its user id #
@app.route('/add_word', methods=['POST'])
def render_add_word():
    if request.method == "POST":
        maori_word = request.form.get('Maori').title().strip()
        english_word = request.form.get('English').title().strip()
        definition = request.form.get('Definition').lower().strip()
        level = request.form.get('Level').lower().strip()
        if int(level) > 10:
            level = 10
        category = request.form.get('cat_id').lower().strip()[1]
        image = request.form.get('Image').strip()
        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO words (Maori_Word, English_Word, Definition, Level, category, image, last_edited) " \
                "VALUES(?, ?, ?, ?, ?, ?, ?)"
        cur.execute(query, (maori_word, english_word, definition, level, category, image, session['user_id']))
        con.commit()
        con.close()
        return redirect('/admin')


# Deletes a word that the user specifies #
@app.route('/delete_word', methods=['POST'])
def render_delete_word():
    if not is_admin():
        return redirect('/?message=Need+to+be+an+admin.')
    if request.method == "POST":
        word = request.form.get('word_id')
        word = word.split(", ")
        word_id = word[0]
        word_name = word[2]
        return render_template("delete_confirm.html", word_id=word_id, word_name=word_name, type="word")
    return redirect("/admin")


# If the user confirms that they want to delete the word then it removes the word from the database #
@app.route('/delete_word_confirm/<word_id>')
def delete_word_confirm(word_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "DELETE FROM words WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (word_id,))
    con.commit()
    con.close()
    return redirect("/admin")


if __name__ == '__main__':
    app.run()
