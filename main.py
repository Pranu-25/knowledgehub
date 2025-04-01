import streamlit as st
import sqlite3
import bcrypt
import base64
import google.generativeai as genai
from datetime import datetime

# Set Google Gemini AI API Key
GOOGLE_API_KEY = "AIzaSyAroISJ2vUlHCg6hrelebOnX8p0C1XPfUg"
genai.configure(api_key=GOOGLE_API_KEY)

# Database Connection
conn = sqlite3.connect("library.db", check_same_thread=False)
cursor = conn.cursor()

# Function to connect to database
def connect_db():
    return sqlite3.connect("library.db")

# Create Tables
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    password TEXT,
                    role TEXT CHECK(role IN ('user', 'admin')))''')

cursor.execute('''CREATE TABLE IF NOT EXISTS books (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    author TEXT,
                    link TEXT,
                    available INTEGER)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS borrowed_books (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    book_id INTEGER,
                    borrowed_date TEXT,
                    return_date TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(book_id) REFERENCES books(id))''')

cursor.execute('''CREATE TABLE IF NOT EXISTS book_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    book_title TEXT,
                    status TEXT DEFAULT "Pending",
                    FOREIGN KEY(user_id) REFERENCES users(id))''')

conn.commit()

# Hash Password Function
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# Check Password
def check_password(hashed_password, user_password):
    try:
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False 

# Register User
def register_user(username, email, password, role):
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()
    hashed_password = hash_password(password)  
    cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
                   (username, email, hashed_password, role))
    conn.commit()
    conn.close()

# Authenticate User
def authenticate_user(username, password):
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user and check_password(user[3], password):
        return user
    return None

# Logout Function
def logout():
    st.session_state.clear()
    st.success("Logged out successfully! Redirecting to login...")
    st.rerun()

    # Login and Registration Function
def set_background(image_path):
    """Set a background image for the Streamlit app."""
    with open(image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode()
    
    background_style = f"""
    <style>
    .stApp {{
        background-image: url("data:image/png;base64,{encoded_string}");
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
    }}
    </style>
    """
    st.markdown(background_style, unsafe_allow_html=True)


def login_register():
    set_background("image4.png")  # Set background for login/register

    st.title("📚 KNOWLEDGEHUB: Centralized Knowledge Management System")
    
    tabs = st.tabs(["Login", "Register"])
    
    with tabs[0]:  
        st.subheader("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            user = authenticate_user(username, password)
            if user:
                st.session_state["user"] = user
                st.session_state["logged_in"] = True
                st.success("Login Successful! Redirecting...")
                st.rerun()
            else:
                st.error("Invalid Credentials")

    with tabs[1]:  
        st.subheader("Register")
        new_username = st.text_input("Username", key="register_username")
        new_email = st.text_input("Email", key="register_email")
        new_password = st.text_input("Password", type="password", key="register_password")
        role = st.selectbox("Role", ["user", "admin"], key="register_role")
        if st.button("Register"):
            register_user(new_username, new_email, new_password, role)
            st.success("Registration Successful! Please log in.")

# Admin Dashboard
def admin_dashboard():
    set_background("photo4.png")
    st.title("Admin Dashboard")

    if st.button("Logout", key="admin_logout"):
        logout()

    tabs = st.tabs(["Manage Books", "Manage Users", "Track Requests", "Add Users", "Assign Books"])
    

    with tabs[0]:  
        st.subheader("Book Management")
        book_title = st.text_input("Book Title", key="book_title")
        author = st.text_input("Author", key="author")
        link = st.text_input("Book Link", key="book_link")
        if st.button("Add Book"):
            cursor.execute("INSERT INTO books (title, author, link, available) VALUES (?, ?, ?, 1)", 
                           (book_title, author, link))
            conn.commit()
            st.success("Book Added Successfully")
    with tabs[0]:  
        st.subheader("📖 Available Books")

        books = cursor.execute("SELECT title, author, link FROM books WHERE available=1").fetchall()

        if books:
            import pandas as pd
            books_df = pd.DataFrame(books, columns=["Title", "Author", "Link"])
            books_df["Link"] = books_df["Link"].apply(lambda x: f"[🔗 Link]({x})")  

            st.markdown(books_df.to_markdown(index=False), unsafe_allow_html=True)
        else:
            st.info("No books available.")

    with tabs[1]:  
        st.subheader("User Management")
        users = cursor.execute("""
            SELECT u.id, u.username, u.email, u.role, 
                   GROUP_CONCAT(b.title, ', ') AS borrowed_books
            FROM users u
            LEFT JOIN borrowed_books bb ON u.id = bb.user_id
            LEFT JOIN books b ON bb.book_id = b.id
            GROUP BY u.id, u.username, u.email, u.role
        """).fetchall()

        if users:
            import pandas as pd
            users_df = pd.DataFrame(users, columns=["ID", "Username", "Email", "Role", "Borrowed Books"])
            users_df.insert(0, "S.No", range(1, len(users_df) + 1))

            st.dataframe(users_df, hide_index=True, column_config={
                "S.No": "S.No",
                "Username": "User",
                "Email": "Mail ID",
                "Role": "Role",
                "Borrowed Books": "Books Borrowed"
            })
        else:
            st.info("No users found.")
    with tabs[2]:  
        st.subheader("Book Requests")
        # requests = cursor.execute("SELECT id, user_id, book_title FROM book_requests WHERE status='Pending'").fetchall()
        requests = cursor.execute("SELECT br.id as id, br.user_id, br.book_title, u.username FROM book_requests as br inner JOIN users as u on br.user_id = u.id WHERE status='Pending'")
        for req in requests:
            print("-------", req)
            st.write(f"📌 {req[2]} (Requested by User ID: {req[3]})")
            if st.button(f"Approve {req[0]}"):
                cursor.execute("UPDATE book_requests SET status='Approved' WHERE id=?", (req[0],))
                conn.commit()
                st.success("Request Approved")

        # Add Users Tab
    with tabs[3]:  
            st.subheader("Add New User")
            new_username = st.text_input("Username", key="new_user")
            new_email = st.text_input("Email", key="new_email")
            new_password = st.text_input("Password", type="password", key="new_password")
            new_role = st.selectbox("Role", ["user", "admin"], key="new_role")

            if st.button("Add User"):
                hashed_password = hash_password(new_password)  # Ensure password is hashed
                cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
                            (new_username, new_email, hashed_password, new_role))
                conn.commit()
                st.success("User Added Successfully")

    # Assign Books Tab
    with tabs[4]:  
        st.subheader("Assign Books to Users")

        users_list = cursor.execute("SELECT id, username FROM users WHERE role='user'").fetchall()
        books_list = cursor.execute("SELECT id, title FROM books WHERE available=1").fetchall()

        user_options = {user[1]: user[0] for user in users_list}
        book_options = {book[1]: book[0] for book in books_list}

        selected_user = st.selectbox("Select User", list(user_options.keys()), key="assign_user")
        selected_book = st.selectbox("Select Book", list(book_options.keys()), key="assign_book")

        if st.button("Assign Book"):
            user_id = user_options[selected_user]
            book_id = book_options[selected_book]
            cursor.execute("INSERT INTO borrowed_books (user_id, book_id, borrowed_date) VALUES (?, ?, ?)", 
                           (user_id, book_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            cursor.execute("UPDATE books SET available=0 WHERE id=?", (book_id,))
            conn.commit()
            st.success(f"Book '{selected_book}' assigned to {selected_user}")

    # AI Chatbot
    chatbot()

# User Dashboard
def user_dashboard(user_id):
    set_background("imagee2.png")
    st.title("📚 User Dashboard")

    if st.button("Logout", key="user_logout"):
        logout()

    # Tabs for User Actions
    tabs = st.tabs(["Available Books", "Borrow Book", "Return Book", "Request Book"])

    with tabs[0]:  
        st.subheader("📖 Available Books")
    
        books = cursor.execute("SELECT title, author, link FROM books WHERE available=1").fetchall()

        if books:
            import pandas as pd
            books_df = pd.DataFrame(books, columns=["Title", "Author", "Link"])
            books_df["Link"] = books_df["Link"].apply(lambda x: f"[🔗 Link]({x})")  

            st.markdown(books_df.to_markdown(index=False), unsafe_allow_html=True)
        else:
            st.info("No books available.")



    with tabs[1]:  # Borrow Book
        st.subheader("Borrow a Book")
        book_list = cursor.execute("SELECT id, title FROM books WHERE available=1").fetchall()
        book_options = {book[1]: book[0] for book in book_list}

        if book_options:
            selected_book = st.selectbox("Select a Book", list(book_options.keys()))
            borrow_date = st.date_input("Borrow Date")
            return_date = st.date_input("Return Date")

            if st.button("Borrow"):
                book_id = book_options[selected_book]
                cursor.execute("INSERT INTO borrowed_books (user_id, book_id, borrowed_date, return_date) VALUES (?, ?, ?, ?)", 
                            (user_id, book_id, borrow_date.strftime("%Y-%m-%d"), return_date.strftime("%Y-%m-%d")))
                cursor.execute("UPDATE books SET available=0 WHERE id=?", (book_id,))
                conn.commit()
                st.success("Book Borrowed Successfully")
        else:
            st.info("No books available for borrowing.")


    with tabs[2]:  
        st.subheader("Return a Book")
        borrowed_books = cursor.execute("SELECT b.id, bk.title FROM borrowed_books b JOIN books bk ON b.book_id = bk.id WHERE b.user_id=?", (user_id,)).fetchall()
        return_options = {book[1]: book[0] for book in borrowed_books}
        if return_options:
            selected_book = st.selectbox("Select Book to Return", list(return_options.keys()))
            if st.button("Return"):
                book_id = return_options[selected_book]
                cursor.execute("DELETE FROM borrowed_books WHERE book_id=? AND user_id=?", (book_id, user_id))
                cursor.execute("UPDATE books SET available=1 WHERE id=?", (book_id,))
                conn.commit()
                st.success("Book Returned Successfully")

    with tabs[3]:  
        st.subheader("Request a Book")
        book_name = st.text_input("Book Name")
        if st.button("Request"):
            cursor.execute("INSERT INTO book_requests (user_id, book_title) VALUES (?, ?)", (user_id, book_name))
            conn.commit()
            st.success("Book Request Submitted Successfully")



    # AI Chatbot
    chatbot()
    
def clear_chat_input():
    st.session_state["chat_input"] = ""  # Clear the text input field

def chatbot():
    st.sidebar.title("🤖 Chatbot")

    user_input = st.sidebar.text_input("Ask me something:", key="chat_input")

    if user_input:
        # Check if query is related to the library database
        if any(keyword in user_input.lower() for keyword in ["available books", "borrowed books", "returned books", "requested books", "assign book"]):
            response = query_library_db(user_input)
        else:
            response = query_gemini(user_input)  # Use Gemini AI for general queries

        st.sidebar.write(f"🤖: {response}")

        st.session_state["chat_input"] = ""

# Query Google Gemini AI
def query_gemini(user_query):
    model = genai.GenerativeModel('gemini-2.0-flash')
    response = model.generate_content(user_query)
    return response.text if response and response.text else "❌ No response from AI."

def query_library_db(user_query):
    """Handles user queries related to the library database."""
    conn = sqlite3.connect("library.db")
    cursor = conn.cursor()

    user_query = user_query.lower()

    # Handling queries related to available books
    if "available books" in user_query:
        cursor.execute("SELECT title, author FROM books WHERE available=1")
        books = cursor.fetchall()
        
        if books:
            book_list = "\n".join([f"- {title} by {author}" for title, author in books])
            response = f"📚 Available Books:\n{book_list}"
        else:
            response = "⚠️ No books are currently available."
    
    # Handling queries related to borrowed books
    elif "borrowed books" in user_query or "borrow book" in user_query:
        cursor.execute("""
            SELECT u.username, b.title, bb.borrowed_date, bb.return_date 
            FROM borrowed_books bb
            JOIN users u ON bb.user_id = u.id
            JOIN books b ON bb.book_id = b.id
        """)
        borrowed_books = cursor.fetchall()
        
        if borrowed_books:
            borrowed_list = "\n".join([
                f"- {title} (Borrowed by {username} on {borrowed_date}, Due: {return_date})"
                for username, title, borrowed_date, return_date in borrowed_books
            ])
            response = f"📖 Borrowed Books:\n{borrowed_list}"
        else:
            response = "📖 No books have been borrowed."
    
    # Handling queries related to returned books
    elif "returned books" in user_query or "return book" in user_query:
        cursor.execute("""
            SELECT u.username, b.title, bb.return_date 
            FROM borrowed_books bb
            JOIN users u ON bb.user_id = u.id
            JOIN books b ON bb.book_id = b.id
            WHERE bb.return_date IS NOT NULL
        """)
        returned_books = cursor.fetchall()
        
        if returned_books:
            returned_list = "\n".join([
                f"- {title} (Returned by {username} on {return_date})"
                for username, title, return_date in returned_books
            ])
            response = f"🔄 Returned Books:\n{returned_list}"
        else:
            response = "🔄 No books have been returned recently."
    
    # Handling book requests
    elif "requested books" in user_query or "request book" in user_query:
        cursor.execute("""
            SELECT u.username, br.book_title, br.status 
            FROM book_requests br
            JOIN users u ON br.user_id = u.id
        """)
        requests = cursor.fetchall()
        
        if requests:
            request_list = "\n".join([
                f"- {book_title} (Requested by {username}, Status: {status})"
                for username, book_title, status in requests
            ])
            response = f"📌 Requested Books:\n{request_list}"
        else:
            response = "📌 No book requests found."
    
    else:
        response = "🤖 I'm here to help with library-related questions. Ask me about available books, borrowed books, returned books, or requested books."

    conn.close()
    return response

# Main Function
def main():
    if "logged_in" in st.session_state:
        user = st.session_state["user"]
        if user[4] == "admin":
            admin_dashboard()
        else:
            user_dashboard(user[0])
    else:
        login_register()

if __name__ == "__main__":
    main()