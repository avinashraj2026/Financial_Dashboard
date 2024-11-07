import streamlit as st
import pandas as pd
import plotly.express as px
from hashlib import sha256
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import shutil
import time
import os
import io
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Table, MetaData, ForeignKey, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import select


MAX_FAILED_ATTEMPTS = 5  # Maximum allowed failed attempts
LOCKOUT_DURATION = 30  # Lockout duration in seconds 

# Database Setup
DATABASE_URL = 'sqlite:///personal_finance.db'
engine = create_engine(DATABASE_URL)
metadata = MetaData()
Session = sessionmaker(bind=engine)
session = Session()


# Define Tables
# Define the users table with salt
users = Table(
    'users', metadata,
    Column('id', Integer, primary_key=True),
    Column('username', String, unique=True),
    Column('password', String),
    Column('salt', String)  # Add salt column
)


# Modify the transactions table to include user_id
transactions = Table(
    'transactions', metadata,
    Column('id', Integer, primary_key=True),
    Column('date', Date),
    Column('amount', Float),
    Column('type', String),
    Column('category', String),
    Column('description', String),
    Column('user_id', Integer, ForeignKey('users.id'))  # Adding user_id to link transactions to users
)

# Modify the budgets table to include user_id
budget_table = Table(
    'budgets', metadata,
    Column('id', Integer, primary_key=True),
    Column('category', String),
    Column('amount', Float),
    Column('user_id', Integer)  # Add user_id to link with users table
)

# Create Tables if Not Exist
metadata.create_all(engine)


#-------------------------------------------------------------------------------------------------------------------
#Function definitions


encryption_key = b'5hoErGlC7VZPX2blekDUIczRFGIWw1smnUPmToEYli0='  
cipher_suite = Fernet(encryption_key)

# Function to encrypt data
def encrypt_data(data):
    if isinstance(data, (int, float)):
        data = str(data)  # Convert numbers to string
    return cipher_suite.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

# Paths for database and backup
db_file = 'C:\\Users\\advai\\Desktop\\IS lab\\personal_finance.db'
backup_dir = 'C:\\Users\\advai\\Desktop\\IS lab\\backups'

# Backup Database Function (User-Specific)
def backup_database(user_id):
    # Ensure the backup directory exists
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    # Timestamp and user-specific file name
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(backup_dir, f'user_{user_id}_backup_{timestamp}.db')
    
    try:
        shutil.copy(db_file, backup_file)
        return True, backup_file  # Success flag and backup file path
    except Exception as e:
        return False, str(e)  # Failure flag and error message

# List Backups Function (User-Specific)
def list_backups(user_id):
    # List only files that match the user_id pattern
    backups = [file for file in os.listdir(backup_dir) if file.startswith(f'user_{user_id}_') and file.endswith('.db')]
    return sorted(backups, reverse=True)  # Sort by newest first

# Restore Backup Function (User-Specific)
def restore_backup(user_id, selected_backup):
    # Ensure the selected backup file belongs to the user
    if not selected_backup.startswith(f'user_{user_id}_'):
        return False, "Unauthorized backup file selected."

    try:
        backup_file_path = os.path.join(backup_dir, selected_backup)
        shutil.copy(backup_file_path, db_file)  # Replace the current database with the backup
        return True, f"Successfully restored from {selected_backup}."
    except Exception as e:
        return False, str(e)

    

#--------------------------------------------------------------------------------------------------------------



# The rest of your code continues...
# Set page configuration
st.set_page_config(page_title="Personal Finance Dashboard", layout="wide")
# Apply Custom CSS for Aesthetic Improvements
st.markdown(
    """
    <style>
    body { background-color: #f9f9f9; font-family: 'Arial', sans-serif; margin: 0; }
    .header-container { background-color: #0077b6; color: white; padding: 2rem; text-align: center; border-radius: 10px; box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1); }
    .title { font-size: 2.5rem; font-weight: bold; margin: 0; }
    .stButton > button { 
        background-color: #0077b6; 
        color: white; 
        font-size: 1.1rem; 
        border-radius: 5px; 
        transition: background-color 0.3s; 
        display: flex; /* Flexbox for alignment */
        align-items: center; /* Center align items vertically */
    }
    .stButton > button:hover { background-color: #005f8d; }
    
    /* Target the SVG icons specifically */
    .stButton > button svg { 
        fill: white; /* Set icon color to white */
        margin-right: 0.5rem; /* Space between icon and text */
    }

    /* Override default button styles to set color */
    .stButton > button:has(svg) {
        background-color: #0077b6; /* Ensures background remains blue */
    }

    .footer { text-align: center; color: grey; margin-top: 3rem; font-size: 0.9rem; padding: 1rem; border-top: 1px solid #e0e0e0; }
    .card { padding: 1rem; border-radius: 10px; background-color: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
    .stApp { max-width: 100%; } /* Make the app full width */
    .logout-button-container {
        position: absolute;
        top: 20px; /* Adjust the top position */
        right: 20px; /* Adjust the right position */
        z-index: 1; /* Ensure it appears above other elements */
    }
    </style>
    """,
    unsafe_allow_html=True
)



# Header Section
st.markdown('<div class="header-container"><p class="title">Personal Finance Dashboard</p></div>', unsafe_allow_html=True)

# State for authentication
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Landing Page
if not st.session_state.authenticated:
    st.title("Welcome to Your Personal Finance Dashboard")
    st.write("Manage your finances effectively.")
    
    col1, col2 = st.columns(2)

    with col1:
        if st.button("Login", key="login_button"):
            st.session_state.auth_action = "login"

    with col2:
        if st.button("Register", key="register_button"):
            st.session_state.auth_action = "register"


    # Initialize session state for login attempts
    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = 0
        st.session_state.lockout_time = None

    # Show Login/Register Form based on action
    if 'auth_action' in st.session_state:
        auth_choice = st.session_state.auth_action
        username = st.text_input("Username", help="Enter your username.").strip()
        password = st.text_input("Password", type='password', help="Enter your password.").strip()

        if auth_choice == "register":
            if st.button("Register", key="register_form_button"):
                with st.spinner("Registering..."):
                    time.sleep(2)
                    existing_user = session.execute(select(users).where(users.c.username == username)).fetchone()
                    if existing_user:
                        st.error("Username already exists. Please choose a different one.")
                    else:
                        # Generate a random salt
                        salt = os.urandom(16).hex()  # Generate a 16-byte random salt

                        # Hash the password with the salt
                        hashed_password = sha256((salt + password).encode()).hexdigest()

                        # Insert the new user with the salt
                        insert_stmt = users.insert().values(username=username, password=hashed_password, salt=salt)
                        try:
                            # Insert the new user and retrieve the user ID
                            result = session.execute(insert_stmt)
                            session.commit()
                            
                            # Get the user ID of the newly registered user
                            new_user_id = result.inserted_primary_key[0]
                            
                            # Store the user_id in session state
                            st.session_state.user_id = new_user_id
                            
                            session.commit()
                            
                            st.success(f"User {username} registered successfully!")
                            st.session_state.authenticated = True  # Auto-login after registration
                            del st.session_state.auth_action  # Remove auth_action to stop showing form
                            st.session_state.homepage_displayed = False  # Reset homepage display state
                        except Exception as e:
                            st.error(f"Registration failed: {str(e)}")



        elif auth_choice == "login":

             # Check for lockout
            if st.session_state.lockout_time:
                time_remaining = st.session_state.lockout_time - time.time()
                if time_remaining > 0:
                    st.error(f"Account locked. Try again in {int(time_remaining)} seconds.")
                else:
                    # Reset lockout
                    st.session_state.lockout_time = None
                    st.session_state.failed_attempts = 0


            if st.button("Login", key="login_form_button"):
                if st.session_state.lockout_time:
                    st.error("Your account is temporarily locked. Please try again later.")
                
                else:# Login logic here
                    with st.spinner("Logging in..."):
                        time.sleep(0.7)
                        # Retrieve the user data from the database
                        select_stmt = select(users).where(users.c.username == username)
                        result = session.execute(select_stmt).fetchone()

                        if result:
                            # Get the stored salt and hashed password
                            salt = result.salt  # Assuming the salt is in the second column
                            stored_hashed_password = result.password  # Assuming the hashed password is in the third column

                            # Hash the entered password with the stored salt
                            hashed_password_attempt = sha256((salt + password).encode()).hexdigest()

                            if stored_hashed_password == hashed_password_attempt:
                                st.success(f"Welcome, {username}!")
                                st.session_state.authenticated = True  # Set authentication status
                                st.session_state.user_id = result.id  # Store user_id from the database
                                del st.session_state.auth_action  # Remove auth_action to stop showing form
                                st.session_state.homepage_displayed = False  # Reset homepage display state
                                st.session_state.failed_attempts = 0  # Reset failed attempts
                            else:
                                st.error("Invalid username or password")
                                st.session_state.failed_attempts += 1

                                # Lock account after too many failed attempts
                                if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                                    st.error(f"Too many failed attempts. Your account is locked for {LOCKOUT_DURATION} seconds.")
                        else:
                            st.error("User doesn't exist")



# After Authentication
if st.session_state.authenticated:
    if 'homepage_displayed' not in st.session_state or not st.session_state.homepage_displayed:
        st.title("Homepage")
        st.write("You are successfully logged in!")
        if st.button("Go to Dashboard"):
            st.session_state.homepage_displayed = True  # Mark homepage as displayed


# Logout Button
if st.session_state.authenticated:
    # Create a container for the button with the new CSS class
    st.markdown('<div class="logout-button-container">', unsafe_allow_html=True)
    if st.button("Logout", key="logout_button", help="Logout from your account"):
        st.session_state.authenticated = False
        del st.session_state.user_id  # Clear the user ID on logout
        st.rerun()  # Rerun the app to reflect changes
    st.markdown('</div>', unsafe_allow_html=True)



# Sidebar Navigation after authentication
if st.session_state.authenticated and st.session_state.homepage_displayed:
    st.sidebar.header("Navigation")
    selected_tab = st.sidebar.radio("Go to", ["Financial Tracking", "Budgeting", "Security", "Backup & Recovery", "Logout"])


    # Financial Tracking Tab
    if selected_tab == "Financial Tracking":
        st.header("Track Your Finances")

        # Transaction Form
        with st.form("transaction_form"):
            date = st.date_input("Date", datetime.now())
            type_choice = st.radio("Type", ["Income", "Expense"], horizontal=True)
            amount = st.number_input("Enter Amount", min_value=0.0, step=1.0)
            description = st.text_input("Description")
            submitted = st.form_submit_button("Add Transaction")

            if submitted:
                if amount <= 0:
                    st.error("Please enter a positive amount.")
                else:
                    # Encrypt amount and description before inserting into the database
                    encrypted_description = encrypt_data(description)

                    new_transaction = {
                        "date": date,
                        "amount": amount,
                        "type": type_choice,
                        "description": encrypted_description,
                        "user_id": st.session_state.user_id  # Include the logged-in user's ID
                    }
                    insert_stmt = transactions.insert().values(new_transaction)
                    session.execute(insert_stmt)
                    session.commit()
                    st.success(f"{type_choice} of {amount} added!")

                    # Debugging log
                    print("Transaction added:", new_transaction)



        # Filter Transactions Section
        st.subheader("Filter Transactions")
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=30), key='start_date')
        end_date = st.date_input("End Date", datetime.now(), key='end_date')
        filter_type = st.selectbox("Filter by Type", ["All", "Income", "Expense"])
        filter_description = st.text_input("Filter by Description", key='filter_description').strip().lower()

        # Display Transaction History
        st.subheader("")  # Placeholder for removing title

        # Query to get transactions for the logged-in user
        select_stmt = select(transactions).where(transactions.c.user_id == st.session_state.user_id)
        df = pd.DataFrame(session.execute(select_stmt).fetchall(), columns=transactions.columns.keys())

        if not df.empty:
            # Decrypt description after fetching from the database
            df['description'] = df['description'].apply(decrypt_data)
            
            # Apply Filters
            filtered_df = df.copy()

            # Apply type filter
            if filter_type != "All":
                filtered_df = filtered_df[filtered_df['type'] == filter_type]

            # Apply date filter
            filtered_df = filtered_df[(filtered_df['date'] >= start_date) & (filtered_df['date'] <= end_date)]

            # Apply description filter
            if filter_description:
                filtered_df = filtered_df[filtered_df['description'].str.lower().str.contains(filter_description)]

            # Drop the 'category' column from the DataFrame before displaying (as per your instructions)
            if 'category' in filtered_df.columns:
                filtered_df = filtered_df.drop(columns=['category'])

            st.dataframe(filtered_df)

            # Financial Visualizations
            st.markdown("### Financial Overview")
            fig = px.bar(filtered_df, x='date', y='amount', color='type', barmode='group', title="Income and Expenses Over Time")

            # Update the layout of the bar chart
            fig.update_layout(
                title_font=dict(size=24, color='#0077b6'),  # Title color
                xaxis_title=dict(font=dict(size=18)),        # X-axis title font size
                yaxis_title=dict(font=dict(size=18)),        # Y-axis title font size
                legend=dict(title="", orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)  # Legend styling
            )

            st.plotly_chart(fig, use_container_width=True)

            # Create columns for pie charts
            col1, col2 = st.columns(2)

            # Pie chart for Income
            with col1:
                income_data = filtered_df[filtered_df['type'] == 'Income']
                if not income_data.empty:
                    income_fig = px.pie(income_data, values='amount', names='description', title='Income Breakdown')
                    st.plotly_chart(income_fig)

            # Pie chart for Expenses
            with col2:
                expense_data = filtered_df[filtered_df['type'] == 'Expense']
                if not expense_data.empty:
                    expense_fig = px.pie(expense_data, values='amount', names='description', title='Expense Breakdown')
                    st.plotly_chart(expense_fig)

            # Display Generate Report Button
            if st.button("Generate Report"):
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    filtered_df.to_excel(writer, index=False, sheet_name='Transactions')
                output.seek(0)
                st.download_button("Download Excel Report", data=output, file_name="transactions_report.xlsx", mime="application/vnd.ms-excel")

        else:
            st.info("No transactions found for the selected filters.")



    
    # Budgeting Tab
    elif selected_tab == "Budgeting":
        st.header("Set Your Monthly Budget")

        # Budget Overview
        st.subheader("Current Budgets")

        # Create the table if it does not exist (this is fine at the global level)
        metadata.create_all(engine)

        # Display current budgets
        # Query to get budgets for the logged-in user
        select_budget_stmt = select(budget_table).where(budget_table.c.user_id == st.session_state.user_id)
        current_budgets = pd.DataFrame(session.execute(select_budget_stmt).fetchall(), columns=budget_table.columns.keys())

        if not current_budgets.empty:
            # Decrypt budget categories before displaying
            current_budgets['category'] = current_budgets['category'].apply(decrypt_data)
            st.dataframe(current_budgets)

        budget_category = st.text_input("Enter Category", placeholder="e.g., Transport, Groceries")
        budget_amount = st.number_input("Set Budget Amount", min_value=0.0, step=1.0)

        if st.button("Save Budget"):
            # Encrypt category before saving
            encrypted_category = encrypt_data(budget_category)

            insert_budget_stmt = budget_table.insert().values(
                category=encrypted_category, 
                amount=budget_amount,  # Leave amount unencrypted
                user_id=st.session_state.user_id  # Include the logged-in user's ID
            )
            session.execute(insert_budget_stmt)
            session.commit()
            st.success(f"Budget of {budget_amount} for {budget_category} saved!")

        # Calculate total spending for each category
        # Notify user of current spending vs budget
        st.subheader("Budget vs Actual Spending")

        if not current_budgets.empty:
            # Calculate total spending for each category for the logged-in user
            total_spending_stmt = select(transactions.c.description, transactions.c.amount).where(
                transactions.c.type == "Expense",
                transactions.c.user_id == st.session_state.user_id  # Filter by user
            )

            # Fetch expenses
            expenses = pd.DataFrame(session.execute(total_spending_stmt).fetchall(), columns=['description', 'amount'])

            # Decrypt descriptions
            expenses['description'] = expenses['description'].apply(decrypt_data)  # Apply decryption to descriptions

            # Ensure amounts are numeric for calculations
            expenses['amount'] = pd.to_numeric(expenses['amount'], errors='coerce')  # Ensure amounts are numeric

            # Sum expenses by description
            description_totals = expenses.groupby('description').sum().reset_index().rename(columns={'amount': 'spent'})

            # Merge with budgets based on description
            budget_summary = pd.merge(
                current_budgets.rename(columns={'amount': 'budgeted', 'category': 'description'}), 
                description_totals, 
                on='description', 
                how='left'
            ).fillna(0)

            # Ensure budgeted and spent are numeric for calculations
            budget_summary['budgeted'] = pd.to_numeric(budget_summary['budgeted'], errors='coerce')
            budget_summary['spent'] = pd.to_numeric(budget_summary['spent'], errors='coerce')

            # Calculate remaining budget
            budget_summary['remaining'] = budget_summary['budgeted'] - budget_summary['spent']



            # Display budget summary
            st.dataframe(budget_summary)

            # Visualize budget vs spending
            fig = px.bar(budget_summary, x='description', y=['budgeted', 'spent'], barmode='group', 
                        title="Budget vs Actual Spending", 
                        labels={'value': 'Amount', 'variable': 'Type'}, 
                        template='plotly_white')
            st.plotly_chart(fig)

                        # Check if any budgets are exceeded
            exceeded_budgets = budget_summary[budget_summary['spent'] > budget_summary['budgeted']]
            if not exceeded_budgets.empty:
                st.error("🚨 Your budget has been exceeded in the following categories:")
                st.dataframe(exceeded_budgets[['description', 'budgeted', 'spent']])
            

        # Budget History
        st.subheader("Budget History")
        if st.button("Show Budget History"):
            history_stmt = select(budget_table).where(budget_table.c.user_id == st.session_state.user_id)
            budget_history = pd.DataFrame(session.execute(history_stmt).fetchall(), columns=budget_table.columns.keys())
            if not budget_history.empty:
                # Decrypt budget history before displaying
                budget_history['category'] = budget_history['category'].apply(decrypt_data)
                budget_history['amount'] = budget_history['amount']  # Leave amount unencrypted
                st.dataframe(budget_history)
            else:
                st.write("No budget history available.")


    
    
    # Security Tab
    elif selected_tab == "Security":
        st.header("Security Features")
        st.write("Your data is protected using Fernet encryption and SHA-256 hashing.")
        st.write("Passwords - hashed using SHA-256 and salted")
        st.write("data encrypted using Fernet and stored")
        st.subheader("Protection against Attacks:")
        st.write("Brute Force:")
        st.write("1) Implemented account lockout mechanisms")
        st.write("2) Implemented rate limiting i.e. wrong password cant be entered more than 5 times")
        st.write("SQL Injections:")
        st.write("1) Used Parameterized Queries")
        st.write("2) Used ORM - SQLAlchemy")


    # Backup and Recovery Tab
    elif selected_tab == "Backup & Recovery":
        st.header("Backup and Recovery")
        st.write("We ensure secure backups and recovery options to prevent data loss.")
        
        user_id = st.session_state.user_id  # Retrieve the logged-in user ID

        # Backup Creation
        if st.button("Backup Now", help="Create a backup of your data", icon="📦"):
            with st.spinner("Creating backup..."):
                success, message = backup_database(user_id)
            
            if success:
                st.success(f"Backup created successfully at: {message}", icon="✅")
            else:
                st.error(f"Error creating backup: {message}", icon="❌")

        # Available Backups for the User
        available_backups = list_backups(user_id)
        selected_backup = st.selectbox("Select Backup to Restore", available_backups)

        # Backup Restoration
        if st.button("Restore Backup", help="Restore selected backup", icon="🔄"):
            success, message = restore_backup(user_id, selected_backup)
            if success:
                st.success(message)
            else:
                st.error(message)


    # Logout Button
    elif st.sidebar.button("Logout"):
        st.session_state.authenticated = False  # Set authentication status to False
        del st.session_state.user_id  # Clear user ID
        st.success("You have been logged out.")
        st.rerun()  # Rerun the app to refresh the state

        if st.button("Recover Database"):
            backup_file_path = "C:\\Users\\advai\\Desktop\\IS lab\\backups"  # Set your backup file path
            db_file_path = "C:/Users/advai/Desktop/IS lab/personal_finance.db"  # Path to your current database
            
            # Call the recovery function
            recovery_message = recover_database(backup_file_path, db_file_path)
            st.success(recovery_message)



# Footer
st.markdown(
    """
    <style>
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        text-align: center;
        background-color: #f1f1f1;
        padding: 10px;
    }
    </style>
    <div class="footer">
        Developed by Advait, Tarini, Avinash
    </div>
    """,
    unsafe_allow_html=True
)
