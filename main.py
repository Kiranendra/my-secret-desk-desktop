from tkinter.ttk import Notebook, Frame, Treeview
from tkinter import Tk, Label, Button, Entry, Text, StringVar, Spinbox
from tkinter.messagebox import showinfo, showerror
from sqlite3 import connect
from time import localtime
from tkcalendar import Calendar
from base64 import b64encode, b64decode
from webbrowser import open_new
from msd.cipher import get_db_path, encrypted, decrypted
from msd.secret import check_db, check_data, secret

global root
root = None

########################
##### GENERAL FUNCTIONS ######
########################
def visit_website():
    open_new("https://kiranendra.github.io/msd/")

def encrypt_value(value):
    return encrypted(value)

def decrypt_value(value):
    return decrypted(value)

def close_application():
    msd_window.destroy()

def do_nothing():
    pass  

def create_tables():
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS msd_notes (title TEXT, date TEXT, time TEXT, notes  TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS msd_appointments (name TEXT, date TEXT, time TEXT, description TEXT, status TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS msd_passwords (web_desc TEXT, username TEXT, password TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS msd_login (password TEXT)")
        cur.close()
        con.close()
    else:
        showerror("Error", "Error while creating the tables")

def create_login(user_pass):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("INSERT INTO msd_login (password) VALUES (?)", (encrypt_value(user_pass), ))
        con.commit()
        cur.close()
        con.close()
        showinfo("Thank you!", "Please login again")
        root.destroy()
        exit()
    else:
        showerror("Error", "Error while creating login")

def check_is_login_available():
    p = get_db_path()
    got_pass = None
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("SELECT password FROM msd_login")
        got_pass = cur.fetchone()
        cur.close()
        con.close()
    else:
        showerror("Error", "Error while checking login")
    if got_pass == None:
        return None
    else:
        return decrypt_value(got_pass[0])

def validate_create_login(user_pass_1, user_pass_2):
    if user_pass_1 == user_pass_2 and not user_pass_1 == '':
        create_login(user_pass_1)
    elif user_pass_1 == '' or user_pass_2 == '':
        showerror("Error!", "Empty passwords not allowed")
    else:
        showerror("Error!", "Passwords did not match")

def validate_login(user_pass, db_pass):
    if not user_pass == db_pass:
        showerror("Error!", "Invalid password")
    else:
        root.destroy()
        main()

########################
##### TAB 1 - FUNCTIONS ######
########################

def get_selected_notes(title):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("""SELECT notes FROM msd_notes WHERE title=:title""", {'title': encrypt_value(title.strip())})
        all_notes = cur.fetchone()
        cur.close()
        con.close()
        return decrypt_value(all_notes[0])
    else:
        showerror("Error", "Error while retreiving notes")

def update_tab_1_treeview():
    for child in tab_1_treeview.get_children():
        tab_1_treeview.delete(child)
    read_notes_from_db()

def read_notes_only_from_db(title):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("""SELECT title FROM msd_notes WHERE title=:title""", {'title': encrypt_value(title)})
        got_title = cur.fetchone()
        cur.close()
        con.close()
        if got_title == None:
            return None
        else:
            return decrypt_value(got_title[0])
    else:
        showerror("Error", "Error while retreiving notes")

def check_notes_title_redundancy(title):
    db_title = read_notes_only_from_db(title)
    if db_title == title:
        return True
    else:
        return False

def save_notes():
    p = get_db_path()
    if p is not None and not check_notes_title_redundancy(title_entry.get().strip()):
        add_notes_button["state"] = "normal"
        open_notes_button["state"] = "normal"
        delete_notes_button["state"] = "normal"
        now_date = str(localtime().tm_year) + '-' + str(localtime().tm_mon) + '-' + str(localtime().tm_mday)
        now_time = str(localtime().tm_hour) + ':' + str(localtime().tm_min)  + ':' + str(localtime().tm_sec)
        con = connect(p)
        cur = con.cursor()
        cur.execute("INSERT INTO msd_notes (title, date, time, notes) VALUES (?, ?, ?, ?)", (encrypt_value(title_entry.get().strip()), encrypt_value(now_date), encrypt_value(now_time), encrypt_value(textarea.get("1.0", 'end').strip())))
        con.commit()
        cur.close()
        con.close()
        update_tab_1_treeview()
        window.destroy()

def update_notes(title, notes):
    p = get_db_path()
    if p is not None:
        add_notes_button["state"] = "normal"
        open_notes_button["state"] = "normal"
        delete_notes_button["state"] = "normal"
        now_date = str(localtime().tm_year) + '-' + str(localtime().tm_mon) + '-' + str(localtime().tm_mday)
        now_time = str(localtime().tm_hour) + ':' + str(localtime().tm_min)  + ':' + str(localtime().tm_sec)
        con = connect(p)
        cur = con.cursor()
        cur.execute("""UPDATE msd_notes SET date=:now_date, time=:now_time, notes=:notes WHERE title=:title""", {'title': encrypt_value(title), 'now_date': encrypt_value(now_date), 'now_time': encrypt_value(now_time), 'notes': encrypt_value(notes)})
        con.commit()
        cur.close()
        con.close()
        update_tab_1_treeview()
        window.destroy()

def notes_cancel():
    add_notes_button["state"] = "normal"
    open_notes_button["state"] = "normal"
    delete_notes_button["state"] = "normal"
    window.destroy()  

def read_notes_from_db():
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("SELECT * FROM msd_notes")
        all_notes = cur.fetchall()
        i = 0
        for row in all_notes:
            tab_1_treeview.insert(parent='', index='end', iid=i, text=decrypt_value(row[0]), values=(decrypt_value(row[2]), decrypt_value(row[1])))
            i += 1
        tab_1_treeview.pack()
        cur.close()
        con.close()

def add_notes():
    add_notes_button["state"] = "disabled"
    open_notes_button["state"] = "disabled"
    delete_notes_button["state"] = "disabled"
    global window
    window = Tk()
    window.title("Add Notes")
    window.geometry("700x560")
    window.resizable(0, 0)
    window.protocol("WM_DELETE_WINDOW", do_nothing)
    notes_label = Label(window, text="Enter Notes Title", font="arial 10", padx=3, pady=5)
    notes_label.pack()
    global title_entry
    title_entry = Entry(window)
    title_entry.pack()
    label = Label(window, text="Enter Your Notes", font="arial 10", padx=3, pady=5)
    label.pack()
    global textarea
    textarea = Text(window)
    textarea.pack()
    button = Button(window, text="OK", command=save_notes)
    button.pack(pady=3)
    button = Button(window, text="Cancel", command=notes_cancel)
    button.pack(pady=3)
    message_label = Label(window, text="*Title must be unique", font="Helvetica 12", pady=3, fg="red")
    message_label.pack()

def open_notes():
    global tab_1_button_message
    if tab_1_treeview.focus() == '':
        tab_1_button_message.set("Please select a notes")
    else:
        add_notes_button["state"] = "disabled"
        open_notes_button["state"] = "disabled"
        delete_notes_button["state"] = "disabled"
        tab_1_button_message.set("")
        selected_notes = get_selected_notes(tab_1_treeview.item(tab_1_treeview.focus())['text'].strip())
        global window
        window = Tk()
        window.title("Your Notes")
        window.geometry("700x550")
        window.resizable(0, 0)
        window.protocol("WM_DELETE_WINDOW", do_nothing)
        notes_label = Label(window, text="Notes Title", font="arial 10", padx=3, pady=5)
        notes_label.pack()
        title_entry = Entry(window)
        title_entry.insert(0, tab_1_treeview.item(tab_1_treeview.focus())['text'].strip())
        title_entry.pack()
        title_entry['state'] = 'disabled'
        label = Label(window, text="Your Notes", font="arial 10", padx=3, pady=5)
        label.pack()
        textarea = Text(window)
        textarea.insert(1.0, selected_notes)
        textarea.pack()
        button = Button(window, text="OK", command=lambda: update_notes(title_entry.get().strip(), textarea.get("1.0", 'end').strip()))
        button.pack(pady=3)
        button = Button(window, text="Cancel", command=notes_cancel)
        button.pack(pady=3)

def delete_notes():
    global tab_1_button_message
    if tab_1_treeview.focus() == '':
        tab_1_button_message.set("Please select a notes")
    else:
        p = get_db_path()
        if p is not None:
            tab_1_button_message.set("")
            delete_title = tab_1_treeview.item(tab_1_treeview.focus())['text'].strip()
            con = connect(p)
            cur = con.cursor()
            cur.execute("""DELETE FROM msd_notes WHERE title=:title""", {'title': encrypt_value(delete_title)})
            con.commit()
            cur.close()
            con.close()
            update_tab_1_treeview()

#------------------------------------------

########################
##### TAB 2 - FUNCTIONS ######
########################
    
def read_appointments_from_db():
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("SELECT * FROM msd_appointments")
        all_appointments = cur.fetchall()
        i = 0
        for row in all_appointments:
            tab_2_treeview.insert(parent='', index='end', iid=i, text=decrypt_value(row[0]), values=(decrypt_value(row[2]), decrypt_value(row[1]), decrypt_value(row[4])))
            i += 1
        tab_2_treeview.pack()
        cur.close()
        con.close()

def update_tab_2_treeview():
    for child in tab_2_treeview.get_children():
        tab_2_treeview.delete(child)
    read_appointments_from_db()

def read_appointment_title_from_db(name):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("""SELECT name FROM msd_appointments WHERE name=:name""", {'name': encrypt_value(name)})
        got_name = cur.fetchone()
        cur.close()
        con.close()
        if got_name == None:
            return None
        else:
            return decrypt_value(got_name[0])

def check_apointment_name_redundancy(name):
    db_name = read_appointment_title_from_db(name)
    if db_name == name:
        return True
    else:
        return False

def get_selected_appointments(name):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("""SELECT * FROM msd_appointments WHERE name=:name""", {'name': encrypt_value(name)})
        got_name = cur.fetchone()
        cur.close()
        con.close()
        if got_name == None:
            return None
        else:
            return decrypt_value(got_name[0]), decrypt_value(got_name[3]), decrypt_value(got_name[1]), decrypt_value(got_name[4]), decrypt_value(got_name[2])

def save_appointment():
    p = get_db_path()
    if not check_apointment_name_redundancy(appointment_name_entry.get().strip()) and p is not None:
        add_appointments_button["state"] = "normal"
        open_appointments_button["state"] = "normal"
        delete_appointments_button["state"] = "normal"
        appointment_date = cal.selection_get()
        appointment_time = appointment_time_entry.get().strip()
        con = connect(p)
        cur = con.cursor()
        cur.execute("INSERT INTO msd_appointments (name, date, time, description, status) VALUES (?, ?, ?, ?, ?)", (encrypt_value(appointment_name_entry.get().strip()), encrypt_value(str(appointment_date)), encrypt_value(appointment_time), encrypt_value(appointment_textarea.get("1.0", 'end').strip()), encrypt_value(appointment_status_spinbox.get())))
        con.commit()
        cur.close()
        con.close()
        update_tab_2_treeview()
        window.destroy()

def appointment_cancel():
    add_appointments_button["state"] = "normal"
    open_appointments_button["state"] = "normal"
    delete_appointments_button["state"] = "normal"
    window.destroy()  

def update_appointment(name, new_date, description, new_time, status):
    p = get_db_path()
    if p is not None:
        add_appointments_button["state"] = "normal"
        open_appointments_button["state"] = "normal"
        delete_appointments_button["state"] = "normal"
        con = connect(p)
        cur = con.cursor()
        cur.execute("""UPDATE msd_appointments SET date=:new_date, time=:new_time, description=:description, status=:status WHERE name=:name""", {'name': encrypt_value(name), 'new_date': encrypt_value(new_date), 'new_time': encrypt_value(new_time), 'description': encrypt_value(description), 'status': encrypt_value(status)})
        con.commit()
        cur.close()
        con.close()
        update_tab_2_treeview()
        window.destroy()

def add_appointment():
    add_appointments_button["state"] = "disabled"
    open_appointments_button["state"] = "disabled"
    delete_appointments_button["state"] = "disabled"
    global window
    window = Tk()
    window.title("Add Appointment")
    window.geometry("700x670")
    window.resizable(0, 0)
    window.protocol("WM_DELETE_WINDOW", do_nothing)
    appointment_name_label = Label(window, text="Enter Appointment Name", font="arial 10", padx=3, pady=5)
    appointment_name_label.pack()
    global appointment_name_entry
    appointment_name_entry = Entry(window)
    appointment_name_entry.pack()
    desc_label = Label(window, text="Enter Description", font="arial 10", padx=3, pady=5)
    desc_label.pack()
    global appointment_textarea
    appointment_textarea = Text(window, height=10)
    appointment_textarea.pack()
    appointment_date_label = Label(window, text="Select Appointment Date", font="arial 10", padx=3, pady=5)
    appointment_date_label.pack()
    global cal
    cal = Calendar(window, selectmode='day', year=localtime().tm_year, month=localtime().tm_mon, day=localtime().tm_mday)
    cal.pack()
    appointment_time_label = Label(window, text="Set Appointment Time", font="arial 10", padx=3, pady=5)
    appointment_time_label.pack()
    global appointment_time_entry
    appointment_time_entry = Entry(window, width=10)
    appointment_time_entry.insert(0, "HH:MM")
    appointment_time_entry.pack(padx=3, pady=5)
    appointment_status_label = Label(window, text="Select Appointment Status", font="arial 10", padx=3, pady=5)
    appointment_status_label.pack()
    global appointment_status_spinbox
    appointment_status_spinbox = Spinbox(window, values=('Pending', 'Done'), state='readonly')
    appointment_status_spinbox.pack()
    button = Button(window, text="OK", command=save_appointment)
    button.pack(pady=3)
    button = Button(window, text="Cancel", command=appointment_cancel)
    button.pack(pady=3)
    message_label = Label(window, text="*Appointment name must be unique", font="Helvetica 12", pady=3, fg="red")
    message_label.pack()

def open_appointment():
    global tab_2_button_message
    if tab_2_treeview.focus() == '':
        tab_2_button_message.set("Please select an appointment")
    else:
        add_appointments_button["state"] = "disabled"
        open_appointments_button["state"] = "disabled"
        delete_appointments_button["state"] = "disabled"
        tab_2_button_message.set("")
        appointment_name, appointment_description, appointment_date, appointment_status, appointment_time = get_selected_appointments(tab_2_treeview.item(tab_2_treeview.focus())['text'].strip())
        appointment_year, appointment_month, appointment_day = appointment_date.split('-')
        global window
        window = Tk()
        window.title("Your Appointment")
        window.geometry("700x650")
        window.resizable(0, 0)
        window.protocol("WM_DELETE_WINDOW", do_nothing)
        appointments_label = Label(window, text="Appointment Name", font="arial 10", padx=3, pady=5)
        appointments_label.pack()
        appointment_name_entry = Entry(window)
        appointment_name_entry.insert(0, tab_2_treeview.item(tab_2_treeview.focus())['text'].strip())
        appointment_name_entry.pack()
        appointment_name_entry['state'] = 'readonly'
        label = Label(window, text="Appointment Description", font="arial 10", padx=3, pady=5)
        label.pack()
        textarea = Text(window, height=10)
        textarea.insert(1.0, appointment_description)
        textarea.pack()
        appointment_date_label = Label(window, text="Appointment Date", font="arial 10", padx=3, pady=5)
        appointment_date_label.pack()
        cal = Calendar(window, selectmode='day', year=int(appointment_year), month=int(appointment_month), day=int(appointment_day))
        cal.pack()
        appointment_time_label = Label(window, text="Set Appointment Time", font="arial 10", padx=3, pady=5)
        appointment_time_label.pack()
        appointment_time_entry = Entry(window, width=10)
        appointment_time_entry.insert(0, appointment_time)
        appointment_time_entry.pack(padx=3, pady=5)
        appointment_status_label = Label(window, text="Select Appointment Status", font="arial 10", padx=3, pady=5)
        appointment_status_label.pack()
        status = StringVar(window)
        status.set(appointment_status)
        appointment_status_spinbox = Spinbox(window, values=('Pending', 'Done'), textvariable=status, state='readonly')
        appointment_status_spinbox.pack()
        button = Button(window, text="OK", command=lambda: update_appointment(appointment_name_entry.get().strip(), cal.selection_get(), textarea.get("1.0", 'end').strip(), appointment_time_entry.get().strip(), appointment_status_spinbox.get()))
        button.pack(pady=3)
        button = Button(window, text="Cancel", command=appointment_cancel)
        button.pack(pady=3)

def delete_appointment():
    global tab_2_button_message
    if tab_2_treeview.focus() == '':
        tab_2_button_message.set("Please select an appointment")
    else:
        p = get_db_path()
        if p is not None:
            tab_2_button_message.set("")
            delete_name = tab_2_treeview.item(tab_2_treeview.focus())['text'].strip()
            con = connect(p)
            cur = con.cursor()
            cur.execute("""DELETE FROM msd_appointments WHERE name=:name""", {'name': encrypt_value(delete_name)})
            con.commit()
            cur.close()
            con.close()
            update_tab_2_treeview()
        
#------------------------------------------

########################
##### TAB 3 - FUNCTIONS ######
########################

def read_passwords_from_db():
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("SELECT * FROM msd_passwords")
        all_passwords = cur.fetchall()
        i = 0
        for row in all_passwords:
            tab_3_treeview.insert(parent='', index='end', iid=i, text=decrypt_value(row[0]), values=(decrypt_value(row[1]), decrypt_value(row[2])))
            i += 1
        tab_3_treeview.pack()
        cur.close()
        con.close()

def update_tab_3_treeview():
    for child in tab_3_treeview.get_children():
        tab_3_treeview.delete(child)
    read_passwords_from_db()

def get_selected_passwords(web_desc):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("""SELECT * FROM msd_passwords WHERE web_desc=:name""", {'name': encrypt_value(web_desc)})
        got_data = cur.fetchone()
        cur.close()
        con.close()
        if got_data == None:
            return None
        else:
            return decrypt_value(got_data[0]), decrypt_value(got_data[1]), decrypt_value(got_data[2])

def read_password_desc_from_db(web_desc):
    p = get_db_path()
    if p is not None:
        con = connect(p)
        cur = con.cursor()
        cur.execute("""SELECT web_desc FROM msd_passwords WHERE web_desc=:web_desc""", {'web_desc': encrypt_value(web_desc)})
        got_web_desc = cur.fetchone()
        cur.close()
        con.close()    
        if got_web_desc == None:
            return None
        else:
            return decrypt_value(got_web_desc[0])

def check_password_web_desc_redundancy(web_desc):
    db_web_desc = read_password_desc_from_db(web_desc)
    if db_web_desc == web_desc:
        return True
    else:
        return False

def password_cancel():
    add_passwords_button["state"] = "normal"
    open_passwords_button["state"] = "normal"
    delete_passwords_button["state"] = "normal"
    window.destroy()

def save_password():
    p = get_db_path()
    if not check_password_web_desc_redundancy(web_desc_entry.get().strip()) and p is not None:
        add_passwords_button["state"] = "normal"
        open_passwords_button["state"] = "normal"
        delete_passwords_button["state"] = "normal"
        s_web_desc, s_username, s_password = encrypt_value(web_desc_entry.get().strip()), encrypt_value(username_entry.get().strip()), encrypt_value(password_entry.get().strip())
        con = connect(p)
        cur = con.cursor()
        cur.execute("INSERT INTO msd_passwords (web_desc, username, password) VALUES (?, ?, ?)", (encrypt_value(web_desc_entry.get().strip()), encrypt_value(username_entry.get().strip()), encrypt_value(password_entry.get().strip())))
        con.commit()
        cur.close()
        con.close()
        update_tab_3_treeview()
        window.destroy()

def add_password():
    add_passwords_button["state"] = "disabled"
    open_passwords_button["state"] = "disabled"
    delete_passwords_button["state"] = "disabled"
    global window
    window = Tk()
    window.title("Add Password")
    window.geometry("330x240")
    window.resizable(0, 0)
    window.protocol("WM_DELETE_WINDOW", do_nothing)
    web_desc_label = Label(window, text="Enter Website/Description", font="arial 10", padx=3, pady=5)
    web_desc_label.pack()
    global web_desc_entry
    web_desc_entry = Entry(window)
    web_desc_entry.pack()
    username_label = Label(window, text="Enter Username", font="arial 10", padx=3, pady=5)
    username_label.pack()
    global username_entry
    username_entry = Entry(window)
    username_entry.pack()
    password_label = Label(window, text="Enter Password", font="arial 10", padx=3, pady=5)
    password_label.pack()
    global password_entry
    password_entry = Entry(window)
    password_entry.pack()
    ok_button = Button(window, text="OK", command=save_password)
    ok_button.pack(pady=3)
    cancel_button = Button(window, text="Cancel", command=password_cancel)
    cancel_button.pack(pady=3)
    message_label = Label(window, text="*Website/Description must be unique", font="Helvetica 12", pady=3, fg="red")
    message_label.pack()

def update_password(web_desc, username, password):
    p = get_db_path()
    if p is not None:
        add_passwords_button["state"] = "normal"
        open_passwords_button["state"] = "normal"
        delete_passwords_button["state"] = "normal"
        con = connect(p)
        cur = con.cursor()
        cur.execute("""UPDATE msd_passwords SET username=:username, password=:password WHERE web_desc=:web_desc""", {'web_desc': encrypt_value(web_desc), 'username': encrypt_value(username), 'password': encrypt_value(password)})
        con.commit()
        cur.close()
        con.close()
        update_tab_3_treeview()
        window.destroy()

def open_password():
    global tab_3_button_message
    if tab_3_treeview.focus() == '':
        tab_3_button_message.set("Please select a password")
    else:
        add_passwords_button["state"] = "disabled"
        open_passwords_button["state"] = "disabled"
        delete_passwords_button["state"] = "disabled"
        global window
        window = Tk()
        window.title("Update Password")
        window.geometry("330x230")
        window.resizable(0, 0)
        window.protocol("WM_DELETE_WINDOW", do_nothing)
        web_desc_value, username_value, password_value = get_selected_passwords(tab_3_treeview.item(tab_3_treeview.focus())['text'].strip())
        web_desc_label = Label(window, text="Website/Description", font="arial 10", padx=3, pady=5)
        web_desc_label.pack()
        web_desc_entry = Entry(window)
        web_desc_entry.insert(0, web_desc_value)
        web_desc_entry.pack()
        web_desc_entry['state'] = 'readonly'
        username_label = Label(window, text="Username", font="arial 10", padx=3, pady=5)
        username_label.pack()
        username_entry = Entry(window)
        username_entry.insert(0, username_value)
        username_entry.pack()
        password_label = Label(window, text="Password", font="arial 10", padx=3, pady=5)
        password_label.pack()
        password_entry = Entry(window)
        password_entry.insert(0, password_value)
        password_entry.pack()
        ok_button = Button(window, text="OK", command=lambda: update_password(web_desc_entry.get().strip(), username_entry.get().strip(), password_entry.get().strip()))
        ok_button.pack(pady=3)
        cancel_button = Button(window, text="Cancel", command=password_cancel)
        cancel_button.pack(pady=3)

def delete_password():
    global tab_3_button_message
    if tab_3_treeview.focus() == '':
        tab_3_button_message.set("Please select a password")
    else:
        p = get_db_path()
        if p is not None:
            tab_3_button_message.set("")
            delete_password = tab_3_treeview.item(tab_3_treeview.focus())['text'].strip()
            con = connect(p)
            cur = con.cursor()
            cur.execute("""DELETE FROM msd_passwords WHERE web_desc=:name""", {'name': encrypt_value(delete_password)})
            con.commit()
            cur.close()
            con.close()
            update_tab_3_treeview()

def main():
    global msd_window
    msd_window = Tk()
    msd_window.title("My Secret Desk - MSD")
    msd_window.geometry("800x520")
    msd_window.resizable(0, 0)
    web_button = Button(msd_window, text='Visit Website', command=visit_website)
    web_button.pack(anchor='w', padx=10, pady=5)
    tabs_window = Notebook(msd_window)
    
    ################
    ##### TAB 1 ######
    ###############

    tab_1 = Frame(tabs_window)
    global add_notes_button
    add_notes_button = Button(tab_1, text='Add Notes', command=add_notes)
    add_notes_button.pack(anchor='e', padx=10, pady=10)
    global tab_1_treeview
    tab_1_treeview = Treeview(tab_1, columns=('Title', 'Time', 'Date'))
    tab_1_treeview.heading('#0', text='Title', anchor='w')
    tab_1_treeview.heading('#1', text='Time', anchor='w')
    tab_1_treeview.heading('#2', text='Date', anchor='w')
    tab_1_treeview.column('#0', minwidth=150, width=200)
    tab_1_treeview.column('#1', minwidth=50, width=50)
    tab_1_treeview.column('#2', minwidth=80, width=80)
    read_notes_from_db()
    global open_notes_button
    open_notes_button = Button(tab_1, text="Open", command=open_notes)
    open_notes_button.pack(padx=10, pady=10)
    global delete_notes_button
    delete_notes_button = Button(tab_1, text="Delete", command=delete_notes)
    delete_notes_button.pack(padx=10, pady=10)
    global tab_1_button_message
    tab_1_button_message = StringVar()
    tab_1_button_message.set("")
    tab_1_label_message = Label(tab_1, textvariable=tab_1_button_message, pady=4, fg="red")
    tab_1_label_message.pack()

    #------------------------------------------

    ################
    ##### TAB 2 ######
    ###############

    tab_2 = Frame(tabs_window)
    global add_appointments_button
    add_appointments_button = Button(tab_2, text='Add Appointment', command=add_appointment)
    add_appointments_button.pack(anchor='e', padx=10, pady=10)
    global tab_2_treeview
    tab_2_treeview = Treeview(tab_2, columns=('Name', 'Time', 'Date', 'Status'))
    tab_2_treeview.heading('#0', text='Name', anchor='w')
    tab_2_treeview.heading('#1', text='Time', anchor='w')
    tab_2_treeview.heading('#2', text='Date', anchor='w')
    tab_2_treeview.heading('#3', text='Status', anchor='w')
    tab_2_treeview.column('#0', minwidth=100, width=150)
    tab_2_treeview.column('#1', minwidth=50, width=50)
    tab_2_treeview.column('#2', minwidth=80, width=80)
    tab_2_treeview.column('#3', minwidth=100, width=100)
    read_appointments_from_db()
    global open_appointments_button
    open_appointments_button = Button(tab_2, text="Open", command=open_appointment)
    open_appointments_button.pack(padx=10, pady=10)
    global delete_appointments_button
    delete_appointments_button = Button(tab_2, text="Delete", command=delete_appointment)
    delete_appointments_button.pack(padx=10, pady=10)
    global tab_2_button_message
    tab_2_button_message = StringVar()
    tab_2_button_message.set("")
    tab_2_label_message = Label(tab_2, textvariable=tab_2_button_message, pady=4, fg="red")
    tab_2_label_message.pack()

    #------------------------------------------

    ################
    ##### TAB 3 ######
    ###############

    tab_3 = Frame(tabs_window)
    global add_passwords_button
    add_passwords_button = Button(tab_3, text='Add Password', command=add_password)
    add_passwords_button.pack(anchor='e', padx=10, pady=10)
    global tab_3_treeview
    tab_3_treeview = Treeview(tab_3, columns=('Website/Description', 'Username', 'Password'))
    tab_3_treeview.heading('#0', text='Website/Description', anchor='w')
    tab_3_treeview.heading('#1', text='Username', anchor='w')
    tab_3_treeview.heading('#2', text='Password', anchor='w')
    tab_3_treeview.column('#0', minwidth=150, width=200)
    tab_3_treeview.column('#1', minwidth=100, width=150)
    tab_3_treeview.column('#2', minwidth=100, width=150)
    tab_3_treeview.pack()
    read_passwords_from_db()
    global open_passwords_button
    open_passwords_button = Button(tab_3, text="Update", command=open_password)
    open_passwords_button.pack(padx=10, pady=10)
    global delete_passwords_button
    delete_passwords_button = Button(tab_3, text="Delete", command=delete_password)
    delete_passwords_button.pack(padx=10, pady=10)
    global tab_3_button_message
    tab_3_button_message = StringVar()
    tab_3_button_message.set("")
    tab_3_label_message = Label(tab_3, textvariable=tab_3_button_message, pady=4, fg="red")
    tab_3_label_message.pack()

    #------------------------------------------

    tabs_window.add(tab_1, text='Notes')
    tabs_window.add(tab_2, text='Appointments')
    tabs_window.add(tab_3, text='Passwords')
    tabs_window.pack(expand=1, fill='both', pady=10, padx=10)
    exit_button = Button(msd_window, text='EXIT',  pady=5, command=close_application)
    exit_button.pack(anchor='e', padx=10, pady=3)
    msd_window.protocol("WM_DELETE_WINDOW", do_nothing)
    msd_window.mainloop()

#------------------------------------------

the_pass = None

if check_db():
        paths_data = check_data()
        if paths_data is None:
            secret()
            create_tables()
        else: 
            create_tables()
            the_pass = check_is_login_available()
else: 
    paths_data = check_data()
    if paths_data is None:
        secret()
        create_tables()
    else: 
        create_tables()
        the_pass = check_is_login_available()

#------------------------------------------

if the_pass is not None:
    root = Tk()
    root.resizable(0, 0)
    root.title("MSD - Login")
    root.geometry('250x80')
    label = Label(root, text="Enter Password")
    label.pack()
    entry = Entry(root, show='*')
    entry.pack()
    button = Button(root, text='Login', command=lambda: validate_login(entry.get().strip(), the_pass))
    button.pack(pady=4)
    root.mainloop()
else:
    root = Tk()
    root.resizable(0, 0)
    root.title("MSD - Create Password")
    root.geometry('250x120')
    label_1 = Label(root, text="New Password")
    label_1.pack()
    entry_1 = Entry(root, show='*')
    entry_1.pack()
    label_2 = Label(root, text="Re-enter Password")
    label_2.pack()
    entry_2 = Entry(root, show='*')
    entry_2.pack()
    button = Button(root, text='Create', command=lambda: validate_create_login(entry_1.get().strip(), entry_2.get().strip()))
    button.pack(pady=4)
    root.mainloop()
