# ---------------------------- SET UP ------------------------------- #
import tkinter as tk
from tkinter import messagebox
import random  # To randomly generate a password
import numpy as np
import pandas as pd  # Storing users password data in csv and reading into a pandas dataframe
import base64  # Encoding used to store raw bytes data to to channels that only support text (i.e. csv)
import pandastable  # TKInter widget for displaying dataframes
import bcrypt  # For creating hash of encryption key and for checking the user entered key against it
from Crypto.Cipher import Salsa20  # Stream cipher I use to encrypt the password data

BLACK = '#323131'
GREY = '#c9c2c4'
LETTERS_LOWER = 'a b c d e f g h i j k l m n o p q r s t u v w x y z'.split()
LETTERS_UPPER = 'A B C D E F G H I J K L M N O P Q R S T U V W X Y Z'.split()
NUMBERS = '0 1 2 3 4 5 6 7 8 9'.split()
SYMBOLS = '! ? @ # : & * % $ ^'.split()

key_1 = ''
key_2 = ''

# FIXME: not saving keys entered by user properly to variables. Think it is as call get() before enter mainloop


# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def password_generator():
    """Generates a random password using letters, numbers and symbols"""
    password_letters_lower = [random.choice(LETTERS_LOWER) for _ in range(random.randint(4, 5))]
    password_letters_upper = [random.choice(LETTERS_UPPER) for _ in range(random.randint(4, 5))]
    password_symbols = [random.choice(SYMBOLS) for _ in range(random.randint(2, 4))]
    password_numbers = [random.choice(NUMBERS) for _ in range(random.randint(2, 4))]

    password_list = password_letters_lower + password_letters_upper + password_symbols + password_numbers
    random.shuffle(password_list)
    password = ''.join(password_list)

    password_input.delete(0, 'end')
    password_input.insert(0, password)


# ---------------------------- ENCRYPTION/DECRYPTION ------------------------------- #
def decrypt_dataframe(key):
    """Reads encrypted data from disc, decrypts it and returns the decrypted dataframe.
    Takes the encryption key as an argument."""
    df = pd.read_csv('data2.csv', index_col=0)

    # Extract nonce from the end of the dataframe then drop that row from dataframe
    nonce = df.iloc[-1, 0].encode('utf-8')
    index_to_drop = df.iloc[-1].name
    df = df.drop(labels=index_to_drop, axis=0)

    # Stream cipher set up
    cipher = Salsa20.new(key=key, nonce=nonce)

    # Decrypt data in dataframe
    for col in df.columns:
        df[col] = df[col].apply(lambda a: a.encode('utf-8'))  # Encode to bytes literals for use in cipher
        df[col] = df[col].apply(
            lambda a: base64.b64decode(a))  # decode from base64 (csv-friendly encoding)
        df[col] = df[col].apply(lambda a: cipher.decrypt(a))  # decrypt the data using Salsa20 stream cipher
        df[col] = df[col].apply(lambda a: a.decode('utf-8'))  # Decode from bytes back to a string so can add new data

    return df


def encrypt_dataframe(df, key):
    """Encrypts the dataframe so that it can be written to disc.
    Takes the dataframe and encryption key as arguments."""
    # Stream cipher set up

    # Generate one-time nonce for encryption
    chars = LETTERS_UPPER + LETTERS_LOWER + NUMBERS
    nonce = [random.choice(chars) for _ in range(8)]
    nonce = ''.join(nonce)
    nonce = nonce.encode('utf-8')

    # Instantiate cipher
    cipher = Salsa20.new(key=key, nonce=nonce)

    # Encrypt data in dataframe
    for col in df.columns:
        df[col] = df[col].apply(lambda a: a.encode('utf-8'))  # Encode to bytes literal
        df[col] = df[col].apply(lambda a: cipher.encrypt(a))  # encrypt data using Salsa20 stream cipher
        df[col] = df[col].apply(
            lambda a: base64.b64encode(a))  # Encode to base64 so the data is in a csv-friendly format
        df[col] = df[col].apply(lambda a: a.decode('utf-8'))  # Decode from bytes back to a string so can save to csv

    # Save one-time nonce at the end of the dataframe for decryption next time read of disk
    nonce_to_append = pd.DataFrame([[nonce.decode(), np.NaN, np.NaN]], columns=df.columns)
    df = pd.concat([df, nonce_to_append], axis=0, ignore_index=True)

    return df


# ---------------------------- SAVE PASSWORD ------------------------------- #
def save_details():
    """Appends the website, username/email and password that the user input to the new row of a
    pandas dataframe which is saved in 'data.csv'.
    The data in 'data.csv' is encrypted so needs to be decrypted prior to the new entry being added and
    encrypted again prior to the data being written to disc again"""
    website = website_input.get()
    email = email_input.get()
    password = password_input.get()

    # Read data off disc and decrypt
    global key_1
    df = decrypt_dataframe(key=key_1)

    # Check if entry fields are empty
    if len(website) == 0 or len(email) == 0 or len(password) == 0:
        messagebox.showwarning(title='Empty fields', message="Please ensure you haven't left any fields empty")
        return

    # Check with the user to confirm the entry is correct
    confirmed_entry = messagebox.askokcancel(title='Entry confirmation',
                                             message=f'Will add:\nWebsite: {website}\nUsername: {email}\n'
                                                     f'Password: {password}')

    if confirmed_entry:
        # Check if an entry for the website already exists
        if website in df['Website'].values:
            # Check with user that it is okay to overwrite an existing entry
            confirmed_overwrite = messagebox.askokcancel(title='Overwrite entry',
                                                         message=f"An entry for '{website}' already exists. Would you "
                                                                 f"like to overwrite the existing password?")
            if confirmed_overwrite:
                index = df[df['Website'] == website].index
                df.loc[index, 'Username'] = email  # Replace the existing username just to be sure
                df.loc[index, 'Password'] = password  # Replace the existing password with the new one
        # Else save the user entries to a new row in the dataframe
        else:
            new_row = {df.columns[0]: website, df.columns[1]: email, df.columns[2]: password}
            df = df.append(new_row, ignore_index=True)

        # Re-encrypt and save the updated dataframe to the existing csv file
        df = encrypt_dataframe(df=df, key=key_1)
        df.to_csv('data2.csv')

        # Wipe clear the text in the entry fields
        website_input.delete(0, 'end')
        password_input.delete(0, 'end')
    else:  # If the user does not confirm the entry cancel the add
        return


# ---------------------------- PASSWORD VIEWER ------------------------------- #
def password_viewer():
    """Display the existing saved passwords to the user"""
    password_window = tk.Toplevel(window)
    password_window.title('Password Viewer')
    password_window.geometry('600x350')
    password_window.config(padx=20, pady=20, bg=BLACK)

    global key_1
    df = decrypt_dataframe(key=key_1)
    table = pandastable.Table(password_window, dataframe=df)
    options = {'fontsize': 10, 'cellbackgr': BLACK, 'textcolor': GREY, 'rowselectedcolor': '#878484'}
    pandastable.config.apply_options(options, table)
    table.show()


# ---------------------------- ENCRYPTION KEY ENTRY ------------------------------- #
def encryption_key_setup():
    """Function for setting up an encryption key the first time the user opens the program.
    Checks that the two key entered matches the confirmatory key and checks that the key 32 bytes long.
    Finally, if the key meets the criteria, it is hashed and saved to a text file and the main window is opened
    Takes the two keys entered by the user."""
    global key_1
    global key_2
    key_1 = password_input1.get().encode('utf-8')
    key_2 = confirmation_input.get().encode('utf-8')

    # Check if the two keys entered by the user match and return an error if they don't
    if key_1 != key_2:
        messagebox.showerror(title='Non-matching keys',
                             message='The two encryption keys entered do not match. Please enter matching keys.')

    # Check if the entered key is 32 bytes long and raise error if it is not
    elif len(key_1) != 32:
        messagebox.showerror(title='Key length error',
                             message='The encryption key entered is not 32 bytes long. Please enter a key comprising '
                                     '32 alphanumeric characters')

    # If the two keys match and are the right length then we will save a hash of the key and open main window
    else:
        hashed_key = bcrypt.hashpw(password=key_1, salt=bcrypt.gensalt())  # Create hashed key
        hashed_key = hashed_key.decode('utf-8')
        with open('hashed_key.txt', mode='w') as key_file:
            key_file.write(hashed_key)

        # Close the key entry window and open the main window
        top.destroy()
        window.deiconify()


def encryption_key_check():
    """Checks that the user entered encryption key is correct by comparing to a saved hashed key.
    Takes the key entered by the user as an argument."""
    global key_1
    key_1 = password_input2.get().encode('utf-8')
    with open('hashed_key.txt', mode='r') as key_file:
        hashed_key = key_file.read()
        hashed_key = hashed_key.encode('utf-8')

    # Check if the key matches the saved key and if correct then open the main window
    if bcrypt.checkpw(key_1, hashed_key):
        top.destroy()
        window.deiconify()
    # If key is incorrect then raise error
    else:
        messagebox.showerror(title='Incorrect key', message='The encryption key entered is incorrect. '
                                                            'Please try again.')


# ---------------------------- MAIN UI SETUP ------------------------------- #
# Window set up
window = tk.Tk()
window.title('Password Manager')
window.config(padx=40, pady=40, bg=BLACK)

# Logo set up
canvas = tk.Canvas(height=200, width=200, highlightthickness=0, bg=BLACK)
logo_image = tk.PhotoImage(file='logo.png')
canvas.create_image(100, 100, image=logo_image)
canvas.grid(column=1, row=0)


# Various text labels
website_label = tk.Label(text='Website:', bg=BLACK, fg=GREY, font="Arial 11")
website_label.grid(row=1, column=0, pady=(0, 10))

email_label = tk.Label(text='Email/Username:', bg=BLACK, fg=GREY, font="Arial 11")
email_label.grid(row=2, column=0, pady=(0, 10), padx=(5, 10))

password_label = tk.Label(text='Password:', bg=BLACK, fg=GREY, font="Arial 11")
password_label.grid(row=3, column=0, pady=(0, 10))


# Various buttons
add_button = tk.Button(text='Add', width=40, font="Arial 10", command=save_details)
add_button.grid(row=4, column=1, columnspan=2, pady=(0, 10), sticky="EW")

generate_password_button = tk.Button(text='Generate password', font="Arial 10", command=password_generator)
generate_password_button.grid(row=3, column=2, pady=(0, 10), sticky="EW")

view_passwords_button = tk.Button(text='View passwords', font='Arial 10', command=password_viewer)
view_passwords_button.grid(row=5, column=1, columnspan=2, pady=(10, 10), sticky='EW')


# Various input fields
website_input = tk.Entry(font="Arial 10")
website_input.grid(row=1, column=1, columnspan=2, sticky='EW', pady=(0, 10), ipady=5)
website_input.focus()

email_input = tk.Entry(font="Arial 10")
email_input.grid(row=2, column=1, columnspan=2, sticky='EW', pady=(0, 10), ipady=5)
email_input.insert(0, 't.j.whitehead21@googlemail.com')

password_input = tk.Entry(font="Arial 10")
password_input.grid(row=3, column=1, sticky="EW", pady=(0, 10), padx=(0, 5), ipady=5)

# ---------------------------- KEY ENTRY UI SETUP ------------------------------- #

# Encryption key window
top = tk.Toplevel()
top.title('Encryption Key')
top.config(padx=40, pady=20, bg=BLACK)

# Detect if the user has already set up an encryption key. If the user has never opened the program, the
# 'hashed_key.txt' file will be blank and the program will request that the user establish an encryption key
with open('hashed_key.txt', mode='r') as file:
    contents = file.read()
    if contents == '':  # Check if no encryption key has been created (i.e. is the first time user uses program)

        # Logo
        top_canvas = tk.Canvas(top, height=200, width=200, highlightthickness=0, bg=BLACK)
        logo_image_2 = tk.PhotoImage(file='logo.png')
        top_canvas.create_image(100, 100, image=logo_image_2)
        top_canvas.grid(column=0, row=0)

        # Various labels
        welcome_label = tk.Label(top, text='Welcome to the Password Manager!', font='Arial 10 bold', bg=BLACK, fg=GREY)
        welcome_label.grid(row=1, column=0, pady=(0, 10))
        request_label = tk.Label(top, text='Please set up an encryption key that will be\nused to encrypt your '
                                           'private data.\nThey key must be exactly 32 bytes long \n(i.e. 32 '
                                           'alphanumeric characters & simple symbols)\n You should make the key easy to'
                                           ' remember by,\nfor example, using a sequence of random words.\n\nBe aware ' 
                                           'that if you lose the key there is\nno means to recover it.',
                                 font='Arial 10', bg=BLACK, fg=GREY)
        request_label.grid(row=2, column=0, pady=(0, 10))

        confirmation_label = tk.Label(top, text='Please re-confirm key:', font='Arial 10', bg=BLACK, fg=GREY)
        confirmation_label.grid(row=4, column=0, pady=(0, 10))

        # Encryption key inputs
        password_input1 = tk.Entry(top, font='Arial 10', show='●')
        password_input1.grid(row=3, column=0, pady=(0, 10), ipadx=40)

        confirmation_input = tk.Entry(top, font='Arial 10', show='●')
        confirmation_input.grid(row=5, column=0, pady=(0, 10), ipadx=40)

        # Enter button
        enter_button = tk.Button(top, font='Arial 10', text='Enter',
                                 command=encryption_key_setup)
        enter_button.grid(row=6, column=0, pady=(0, 10))

    # If an encryption key has been created
    else:
        welcome_label = tk.Label(top, text='Welcome to the Password Manager!', font='Arial 10 bold',
                                 bg=BLACK, fg=GREY)
        welcome_label.grid(row=0, column=0, pady=(0, 10))
        key_label = tk.Label(top, text='Please enter encryption key', font='Arial 10', bg=BLACK, fg=GREY)
        key_label.grid(row=1, column=0, pady=(0, 10))

        password_input2 = tk.Entry(top, font='Arial 10', show='●')
        password_input2.grid(row=2, column=0, pady=(0, 10), ipadx=40)

        login_button = tk.Button(top, font='Arial 10', text='Log in',
                                 command=encryption_key_check)
        login_button.grid(row=3, column=0)


window.withdraw()  # Hides the main window until the correct encryption key is entered
window.mainloop()
