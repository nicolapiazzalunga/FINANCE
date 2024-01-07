import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_positions = db.execute("SELECT symbol, position FROM positions \
        WHERE id = :user_id", user_id=session["user_id"])

    answer = [{**lookup(position["symbol"]),
               **{"shares": position["position"]}}
              for position in user_positions]

    portfolio = [{**item, **{"value_of_position": usd(item["shares"]*item["price"])}}
                 for item in answer]

    cash = db.execute("SELECT cash FROM users \
        WHERE id = :user_id", user_id=session["user_id"])[0]["cash"]

    grand_total = cash
    for item in portfolio:
        grand_total = grand_total + item["shares"]*item["price"]

    for item in portfolio:
        item["price"] = usd(item["price"])

    return render_template("index.html", portfolio=portfolio, cash=usd(cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # get user input
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # try isinstance float
        try:
            isinstance(float(shares), float)
        except:
            return apology("Shares must be integer")

        # if modulo one is zero
        if (float(shares) % 1 != 0):
            return apology("Shares must be integer")

        # if shares are negative
        elif int(float(shares)) <= 0:
            return apology("Shares must be a positive value")

        # otherwise cast share into an int
        else:
            shares = int(float(shares))

        # look up stock data
        answer = lookup(symbol)

        # validate symbol
        if answer is None:
            return apology("Invalid symbol")

        # retrieve user cash
        cash = db.execute("SELECT cash FROM users \
            WHERE id = :user_id", user_id=session["user_id"])[0]["cash"]

        # if cash is not enough return apology
        if cash < answer["price"]*shares:
            return apology("Insufficient cash")

        # if cash is enough
        else:
            # insert the transaction in the transactions table
            db.execute("INSERT INTO transactions \
                (trtype, symbol, shares, id) \
                VALUES (:trtype, :symbol, :shares, :user_id)", trtype="buy", symbol=symbol, shares=shares, user_id=session["user_id"])

            # update user cash
            cash = cash - answer["price"]*shares
            db.execute("UPDATE users SET cash = :cash \
                WHERE id = :user_id", cash=cash, user_id=session["user_id"])

            # retrieve user position
            position = db.execute("SELECT position FROM positions \
                WHERE id = :user_id AND symbol = :symbol", symbol=symbol, user_id=session["user_id"])

            # if user has an open position
            if position != []:
                # update user position
                position = position[0]["position"] + shares
                db.execute("UPDATE positions SET position = :position \
                    WHERE id = :user_id AND symbol = :symbol", position=position, user_id=session["user_id"], symbol=symbol)

            # if user does not have an open position
            else:
                # create new position
                position = shares
                db.execute("INSERT INTO positions (id, symbol, position) \
                    VALUES (:user_id, :symbol, :position)", user_id=session["user_id"], symbol=symbol, position=position)

            # create portfolio
            user_positions = db.execute("SELECT symbol, position FROM positions \
                WHERE id = :user_id", user_id=session["user_id"])

            answer = [{**lookup(position["symbol"]),
                       **{"shares": position["position"]}}
                      for position in user_positions]

            portfolio = [{**item, **{"value_of_position": usd(item["shares"]*item["price"])}}
                         for item in answer]

            # compute grand total
            grand_total = cash
            for item in portfolio:
                grand_total = grand_total + item["shares"]*item["price"]

            for item in portfolio:
                item["price"] = usd(item["price"])

            # redirect to portfolio
            return render_template("index.html", portfolio=portfolio, cash=usd(cash), grand_total=usd(grand_total))

    # User reached route via GET (as by submitting a form via GET)
    else:
        return render_template("buy.html")


@app.route("/pwchange", methods=["GET", "POST"])
def pwchange():
    """Change password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        oldpassword = request.form.get("oldpassword")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure old password was submitted
        elif not oldpassword:
            return apology("must provide password", 403)

        # Ensure new password was submitted
        elif not newpassword:
            return apology("must provide new password", 403)

        # Ensure new password was confirmed
        elif not confirmation:
            return apology("must confirm new password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users \
            WHERE username = :username", username=username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], oldpassword):
            return apology("invalid username and/or password", 403)

        # ensure new password is correctly confirmed
        if newpassword != confirmation:
            return apology("passwords do not match", 403)

        # update users table
        db.execute("UPDATE users SET hash = :hashed_pw \
            WHERE id = :user_id", hashed_pw=generate_password_hash(newpassword), user_id=rows[0]["id"])

        return render_template("login.html")
    # User reached route via GET (as by submitting a form via GET)
    else:
        return render_template("pwchange.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    data = request.args.get("username")
    answer = db.execute("SELECT username FROM users \
        WHERE username = :username", username=data)

    if answer == []:
        data = True
    else:
        data = False

    data = jsonify(data)
    return data


@app.route("/history", methods=["GET"])
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM transactions WHERE id = :user_id", user_id=session["user_id"])
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users \
            WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        symbol = request.form.get("symbol")
        answer = lookup(symbol)

        # validate symbol
        if answer is None:
            return apology("Invalid symbol")

        answer['price'] = usd(answer['price'])
        return render_template("quote.html", answer=answer, givequote=True)

    # User reached route via GET (as by submitting a form via GET)
    else:
        return render_template("quote.html", askquote=True)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # get username and password
        username = request.form.get("username")
        password = request.form.get("password")

        # ensure username was provided
        if not username:
            return apology("must provide username", 400)

        # ensure password was provided
        elif not password:
            return apology("must provide password", 400)

        # ensure password confirmation was provided
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # ensure passwords match
        elif password != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # check if user is in database
        if db.execute('SELECT id FROM users \
            WHERE username = :username', username=username) != []:
            return apology("User {} is already registered".format(username), 400)

        # insert user in database and redirect to /login
        else:
            db.execute('INSERT INTO users (username, hash) \
                VALUES (:username,:hashed_pw)', username=username, hashed_pw=generate_password_hash(password))
            return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # get user input
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # try isinstance float
        try:
            isinstance(float(shares), float)
        except:
            return apology("Shares must be integer")

        # if modulo one is zero
        if (float(shares) % 1 != 0):
            return apology("Shares must be integer")

        # if shares are negative
        elif int(float(shares)) <= 0:
            return apology("Shares must be a positive value")

        # otherwise cast share into an int
        else:
            shares = int(float(shares))

        # look up stock data
        answer = lookup(symbol)

        # validate symbol
        if answer is None:
            return apology("Invalid symbol")

        # retrieve user position
        position = db.execute("SELECT position FROM positions \
            WHERE id = :user_id AND symbol = :symbol", symbol=symbol, user_id=session["user_id"])

        # if user does not have a position in the stock
        if position == []:
            return apology("No position open for this stock")

        # if user HAS a position in the stock
        else:
            if position[0]["position"] < shares:
                return apology("Amount unavailable")
            else:
                # post a transaction
                db.execute("INSERT INTO transactions \
                    (trtype, symbol, shares, id) \
                    VALUES (:trtype, :symbol, :shares, :user_id)", trtype="sell", symbol=symbol, shares=shares, user_id=session["user_id"])

                # update position
                position = position[0]["position"] - shares

                db.execute("UPDATE positions SET position = :position \
                    WHERE id = :user_id AND symbol = :symbol", position=position, user_id=session["user_id"], symbol=symbol)

                # update cash
                cash = db.execute("SELECT cash FROM users \
                    WHERE id = :user_id", user_id=session["user_id"])[0]["cash"]

                cash = cash + answer["price"]*shares

                db.execute("UPDATE users SET cash = :cash \
                    WHERE id = :user_id", cash=cash, user_id=session["user_id"])

                # create portfolio
                user_positions = db.execute("SELECT symbol, position FROM positions \
                    WHERE id = :user_id", user_id=session["user_id"])

                answer = [{**lookup(position["symbol"]),
                           **{"shares": position["position"]}}
                          for position in user_positions]

                portfolio = [{**item, **{"value_of_position": usd(item["shares"]*item["price"])}}
                             for item in answer]

                # compute grand total
                grand_total = cash
                for item in portfolio:
                    grand_total = grand_total + item["shares"]*item["price"]

                for item in portfolio:
                    item["price"] = usd(item["price"])

                # render index
                return render_template("index.html", portfolio=portfolio, cash=usd(cash), grand_total=usd(grand_total))

    else:
        user_positions = db.execute("SELECT symbol, position FROM positions \
            WHERE id = :user_id", user_id=session["user_id"])

        return render_template("sell.html", user_positions=user_positions)

    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
