


import tkinter as tk
from tkinter import ttk, messagebox
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import serial
import threading
import time


# AWS Cognito and DynamoDB setup
COGNITO_REGION = "ap-south-1"
COGNITO_USER_POOL_ID = "ap-south-1_HYw5am7jC"
COGNITO_APP_CLIENT_ID = "4pkmdfu5b4a702pp569bl4b1tg"
cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)

dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
books_table = dynamodb.Table('books')         # Replace 'books' with your DynamoDB books table name
borrowed_table = dynamodb.Table('borrowed')   # Replace 'borrowed' with your DynamoDB borrowed table name

borrowed_data = []  # To display borrowed records dynamically in the GUI

# Serial setup for Arduino communication
def initialize_serial():
    try:
        arduino = serial.Serial('COM8', 9600, timeout=1)
        time.sleep(2)  # Allow Arduino to initialize
        return arduino
    except serial.SerialException:
        messagebox.showerror("Connection Error", "Could not connect to Arduino on COM8. Please check the connection.")
        return None

arduino = initialize_serial()

# Global variable to store the logged-in user's name
logged_in_user_name = ""

# Cognito user authentication functions
def sign_up_user(username, password, email, name):
    try:
        cognito_client.sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "name", "Value": name}
            ]
        )
        messagebox.showinfo("Success", "User registered successfully. Please confirm your email.")
        registration_frame.pack_forget()
        verification_frame.pack(fill=tk.X, padx=10, pady=10)
    except Exception as e:
        messagebox.showerror("Sign Up Error", f"Error during sign-up: {e}")

def confirm_user_signup(username, confirmation_code):
    try:
        cognito_client.confirm_sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=username,
            ConfirmationCode=confirmation_code
        )
        messagebox.showinfo("Success", "Email confirmed successfully. Please log in.")
        verification_frame.pack_forget()
        login_frame.pack(fill=tk.X, padx=10, pady=10)
    except Exception as e:
        messagebox.showerror("Confirmation Error", f"Error during confirmation: {e}")

def log_in_user(username, password):
    global logged_in_user_name
    try:
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password
            }
        )
        access_token = response['AuthenticationResult']['AccessToken']
        # Fetch user attributes to get the name
        user_info = cognito_client.get_user(
            AccessToken=access_token
        )
        for attr in user_info['UserAttributes']:
            if attr['Name'] == 'name':
                logged_in_user_name = attr['Value']
                break

        if not logged_in_user_name:
            messagebox.showerror("Login Error", "Could not retrieve user name.")
            return

        messagebox.showinfo("Success", f"Logged in successfully as {logged_in_user_name}.")
        login_frame.pack_forget()
        rfid_scan_frame.pack(fill=tk.X, padx=10, pady=10)
        borrowed_books_frame.pack(fill=tk.X, padx=10, pady=10)  # Show the borrowed books UI after login
        load_borrowed_books()
    except Exception as e:
        messagebox.showerror("Login Error", f"Error during authentication: {e}")

# Function to query books table
def find_book_by_rfid(rfid):
    try:
        response = books_table.get_item(Key={'rfid': rfid})
        if 'Item' in response:
            return response['Item']
        else:
            return None
    except (NoCredentialsError, PartialCredentialsError) as e:
        messagebox.showerror("AWS Error", f"AWS credentials error: {e}")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Error querying DynamoDB: {e}")
        return None

# Function to add entry to borrowed table
def add_to_borrowed_table(customer_name, rfid, book_id, book_name):
    try:
        borrowed_table.put_item(
            Item={
                'customername': customer_name,
                'rfid': rfid,
                'bookid': book_id,
                'bookname': book_name
            }
        )
        # Update local borrowed data
        borrowed_data.append({"Customer Name": customer_name, "RFID": rfid, "Book ID": book_id, "Book Name": book_name})
        update_borrowed_table()
        messagebox.showinfo("Success", f"Book '{book_name}' issued to {customer_name}.")
    except Exception as e:
        messagebox.showerror("Error", f"Error adding to borrowed table: {e}")

# Function to load borrowed books from DynamoDB
def load_borrowed_books():
    try:
        response = borrowed_table.scan()
        borrowed_data.clear()
        for item in response.get('Items', []):
            borrowed_data.append({
                "Customer Name": item.get("customername", ""),
                "RFID": item.get("rfid", ""),
                "Book ID": item.get("bookid", ""),
                "Book Name": item.get("bookname", "")
            })
        update_borrowed_table()
    except Exception as e:
        messagebox.showerror("Error", f"Error loading borrowed books: {e}")

# Function to update borrowed books table in the UI
def update_borrowed_table():
    for item in borrowed_table_tree.get_children():
        borrowed_table_tree.delete(item)

    for record in borrowed_data:
        borrowed_table_tree.insert("", tk.END, values=(
            record["Customer Name"], 
            record["RFID"], 
            record["Book ID"],
            record["Book Name"]
        ))

# Function to read RFID data from Arduino in a separate thread
def read_rfid_from_arduino():
    if arduino and arduino.is_open:
        try:
            arduino.reset_input_buffer()
            # Arduino is already sending RFID data when a tag is scanned
            # So, we just need to read it
            rfid_data = arduino.readline().decode('utf-8').strip()
            if rfid_data:
                process_rfid_data(rfid_data)
            else:
                messagebox.showerror("Error", "No RFID data received. Please try again.")
        except Exception as e:
            messagebox.showerror("Error", f"Error reading from Arduino: {e}")
    else:
        messagebox.showerror("Connection Error", "Arduino is not connected.")

# Function to process the received RFID data
def process_rfid_data(rfid_data):
    book_info = find_book_by_rfid(rfid_data)
    if book_info:
        book_details_label.config(
            text=(
                f"Book Name: {book_info['bookname']}\n"
                f"Author: {book_info['authorname']}\n"
                f"Book ID: {book_info['bookid']}\n"
                f"RFID: {rfid_data}"
            )
        )
        issue_button.config(state=tk.NORMAL)
        rfid_entry.delete(0, tk.END)
        rfid_entry.insert(0, rfid_data)  # Populate the RFID entry field
    else:
        messagebox.showinfo("Not Found", f"No book found for RFID: {rfid_data}")
        book_details_label.config(text="Book details will appear here.")
        issue_button.config(state=tk.DISABLED)

# GUI-related functions
def scan_rfid():
    """Start a thread to read RFID data from Arduino."""
    if arduino and arduino.is_open:
        threading.Thread(target=read_rfid_from_arduino, daemon=True).start()
    else:
        messagebox.showerror("Connection Error", "Arduino is not connected.")

def issue_book():
    """Issue the book."""
    rfid_data = rfid_entry.get().strip()
    customer_name = customer_name_entry.get().strip()
    if not customer_name or not rfid_data:
        messagebox.showwarning("Input Error", "Customer name and RFID cannot be empty.")
        return

    book_info = find_book_by_rfid(rfid_data)
    if book_info:
        add_to_borrowed_table(customer_name, rfid_data, book_info['bookid'], book_info['bookname'])
    else:
        messagebox.showerror("Error", "Book information could not be retrieved.")

    rfid_entry.delete(0, tk.END)
    book_details_label.config(text="Book details will appear here.")
    issue_button.config(state=tk.DISABLED)
    customer_name_entry.delete(0, tk.END)

def logout_user():
    """Logout the current user and return to the login page."""
    global logged_in_user_name
    confirm = messagebox.askyesno("Logout", "Are you sure you want to logout?")
    if confirm:
        # Clear user-related data
        logged_in_user_name = ""
        customer_name_entry.delete(0, tk.END)
        rfid_entry.delete(0, tk.END)
        book_details_label.config(text="Book details will appear here.")
        issue_button.config(state=tk.DISABLED)
        
        # Hide RFID Scan and Borrowed Books frames
        rfid_scan_frame.pack_forget()
        borrowed_books_frame.pack_forget()
        
        # Show Login frame
        login_frame.pack(fill=tk.X, padx=10, pady=10)
        messagebox.showinfo("Logged Out", "You have been logged out successfully.")

def show_registration():
    login_frame.pack_forget()
    verification_frame.pack_forget()
    registration_frame.pack(fill=tk.X, padx=10, pady=10)

def show_login():
    registration_frame.pack_forget()
    verification_frame.pack_forget()
    login_frame.pack(fill=tk.X, padx=10, pady=10)

# GUI Setup
root = tk.Tk()
root.title("Library RFID Management System")
root.geometry("800x600")
root.configure(bg="#f8f9fa")

# Header
header_frame = tk.Frame(root, bg="#343a40", pady=10)
header_frame.pack(fill=tk.X)

header_label = tk.Label(
    header_frame, text="Library RFID Management System", font=("Arial", 18, "bold"), bg="#343a40", fg="#ffffff"
)
header_label.pack()

main_frame = tk.Frame(root, bg="#f8f9fa", pady=20, padx=20)
main_frame.pack(fill=tk.BOTH, expand=True)

# Registration Section
registration_frame = tk.LabelFrame(main_frame, text="User Registration", font=("Arial", 14), bg="#f8f9fa", padx=10, pady=10)

username_label = tk.Label(registration_frame, text="Username:", font=("Arial", 12), bg="#f8f9fa")
username_label.grid(row=0, column=0, padx=5, pady=5)
username_entry = tk.Entry(registration_frame, font=("Arial", 12), width=30)
username_entry.grid(row=0, column=1, padx=10, pady=5)

password_label = tk.Label(registration_frame, text="Password:", font=("Arial", 12), bg="#f8f9fa")
password_label.grid(row=1, column=0, padx=5, pady=5)
password_entry = tk.Entry(registration_frame, font=("Arial", 12), width=30, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)

email_label = tk.Label(registration_frame, text="Email:", font=("Arial", 12), bg="#f8f9fa")
email_label.grid(row=2, column=0, padx=5, pady=5)
email_entry = tk.Entry(registration_frame, font=("Arial", 12), width=30)
email_entry.grid(row=2, column=1, padx=10, pady=5)

name_label = tk.Label(registration_frame, text="Name:", font=("Arial", 12), bg="#f8f9fa")
name_label.grid(row=3, column=0, padx=5, pady=5)
name_entry = tk.Entry(registration_frame, font=("Arial", 12), width=30)
name_entry.grid(row=3, column=1, padx=10, pady=5)

sign_up_button = tk.Button(
    registration_frame, 
    text="Sign Up", 
    command=lambda: sign_up_user(
        username_entry.get().strip(), 
        password_entry.get().strip(), 
        email_entry.get().strip(), 
        name_entry.get().strip()
    ), 
    font=("Arial", 12), 
    bg="#007bff", 
    fg="#ffffff"
)
sign_up_button.grid(row=4, columnspan=2, pady=10)

# Registration navigation button
registration_back_button = tk.Button(
    registration_frame,
    text="Back to Login",
    command=show_login,
    font=("Arial", 10),
    bg="#6c757d",
    fg="#ffffff"
)
registration_back_button.grid(row=5, columnspan=2, pady=5)

# Email Verification Section
verification_frame = tk.LabelFrame(main_frame, text="Verify Email", font=("Arial", 14), bg="#f8f9fa", padx=10, pady=10)

confirmation_code_label = tk.Label(verification_frame, text="Enter Confirmation Code:", font=("Arial", 12), bg="#f8f9fa")
confirmation_code_label.grid(row=0, column=0, padx=5, pady=5)
confirmation_code_entry = tk.Entry(verification_frame, font=("Arial", 12), width=30)
confirmation_code_entry.grid(row=0, column=1, padx=10, pady=5)

confirm_button = tk.Button(
    verification_frame, 
    text="Confirm", 
    command=lambda: confirm_user_signup(
        username_entry.get().strip(), 
        confirmation_code_entry.get().strip()
    ), 
    font=("Arial", 12), 
    bg="#28a745", 
    fg="#ffffff"
)
confirm_button.grid(row=1, columnspan=2, pady=10)

# Verification navigation button (to go back to login)
verification_nav_button = tk.Button(
    verification_frame,
    text="Back to Login",
    command=show_login,
    font=("Arial", 10),
    bg="#6c757d",
    fg="#ffffff"
)
verification_nav_button.grid(row=2, columnspan=2, pady=5)

# Login Section
login_frame = tk.LabelFrame(main_frame, text="User Login", font=("Arial", 14), bg="#f8f9fa", padx=10, pady=10)

login_username_label = tk.Label(login_frame, text="Username:", font=("Arial", 12), bg="#f8f9fa")
login_username_label.grid(row=0, column=0, padx=5, pady=5)
login_username_entry = tk.Entry(login_frame, font=("Arial", 12), width=30)
login_username_entry.grid(row=0, column=1, padx=10, pady=5)

login_password_label = tk.Label(login_frame, text="Password:", font=("Arial", 12), bg="#f8f9fa")
login_password_label.grid(row=1, column=0, padx=5, pady=5)
login_password_entry = tk.Entry(login_frame, font=("Arial", 12), width=30, show="*")
login_password_entry.grid(row=1, column=1, padx=10, pady=5)

login_button = tk.Button(
    login_frame, 
    text="Login", 
    command=lambda: log_in_user(
        login_username_entry.get().strip(), 
        login_password_entry.get().strip()
    ), 
    font=("Arial", 12), 
    bg="#007bff", 
    fg="#ffffff"
)
login_button.grid(row=2, columnspan=2, pady=10)

# Login navigation button
registration_nav_button = tk.Button(
    login_frame,
    text="Register New User",
    command=show_registration,
    font=("Arial", 10),
    bg="#6c757d",
    fg="#ffffff"
)
registration_nav_button.grid(row=3, columnspan=2, pady=5)

# Initially pack the Login frame
login_frame.pack(fill=tk.X, padx=10, pady=10)

# RFID Scan Section (after successful login)
rfid_scan_frame = tk.LabelFrame(main_frame, text="RFID Scan", font=("Arial", 14), bg="#f8f9fa", padx=10, pady=10)

# Customer Name Entry
customer_name_label = tk.Label(rfid_scan_frame, text="Customer Name:", font=("Arial", 12), bg="#f8f9fa")
customer_name_label.grid(row=0, column=0, padx=5, pady=5)
customer_name_entry = tk.Entry(rfid_scan_frame, font=("Arial", 12), width=30)
customer_name_entry.grid(row=0, column=1, padx=10, pady=5)

# RFID Entry
rfid_label = tk.Label(rfid_scan_frame, text="Scan RFID:", font=("Arial", 12), bg="#f8f9fa")
rfid_label.grid(row=1, column=0, padx=5, pady=5)
rfid_entry = tk.Entry(rfid_scan_frame, font=("Arial", 12), width=30)
rfid_entry.grid(row=1, column=1, padx=10, pady=5)

# Scan Button
scan_button = tk.Button(
    rfid_scan_frame, 
    text="Scan", 
    command=scan_rfid, 
    font=("Arial", 12), 
    bg="#007bff", 
    fg="#ffffff"
)
scan_button.grid(row=2, columnspan=2, pady=10)

# Book Details Label
book_details_label = tk.Label(rfid_scan_frame, text="Book details will appear here.", font=("Arial", 12), bg="#f8f9fa")
book_details_label.grid(row=3, columnspan=2, pady=10)

# Issue Book Button
issue_button = tk.Button(
    rfid_scan_frame, 
    text="Issue Book", 
    command=issue_book, 
    font=("Arial", 12), 
    bg="#28a745", 
    fg="#ffffff", 
    state=tk.DISABLED
)
issue_button.grid(row=4, columnspan=2, pady=10)

# Logout Button
logout_button = tk.Button(
    rfid_scan_frame, 
    text="Logout", 
    command=logout_user, 
    font=("Arial", 10), 
    bg="#dc3545", 
    fg="#ffffff"
)
logout_button.grid(row=5, columnspan=2, pady=5)

# Borrowed Books Table (after successful login)
borrowed_books_frame = tk.LabelFrame(main_frame, text="Borrowed Books", font=("Arial", 14), bg="#f8f9fa", padx=10, pady=10)

borrowed_table_tree = ttk.Treeview(borrowed_books_frame, columns=("Customer Name", "RFID", "Book ID", "Book Name"), show="headings")
borrowed_table_tree.heading("Customer Name", text="Customer Name")
borrowed_table_tree.heading("RFID", text="RFID")
borrowed_table_tree.heading("Book ID", text="Book ID")
borrowed_table_tree.heading("Book Name", text="Book Name")
borrowed_table_tree.pack(fill=tk.X, padx=10, pady=10)

# Run the Tkinter event loop
root.mainloop()