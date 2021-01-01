'''

This script contains the functions to validate the key path and database path.

'''
from tkinter import Tk, Label, Button, Entry, StringVar
from sqlite3 import connect
from os.path import exists, isfile, join, basename
from os import getcwd
from time import sleep
from tkinter.messagebox import showerror, showinfo
from base64 import b64encode
from webbrowser import open_new

DBNAME = 'data.db'

def check_db():
    if not exists(join(getcwd(), DBNAME)):
        try:
            con = connect(join(getcwd(), DBNAME))
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS paths (pathname TEXT, path TEXT)")
        except Exception as e: showerror("Error", "{}".format(e))
        finally:
            cur.close()
            con.close()
        return True
    else: return False

def open_key_gen():
    open_new("https://kiranendra.github.io/keygen/")

def check_data():
    con = connect(join(getcwd(), DBNAME))
    cur = con.cursor()
    cur.execute("SELECT * FROM paths")
    check = cur.fetchall()
    cur.close()
    con.close()
    if check == []:
        return None
    else:
        return check

def validate_paths(key_path, db_path):
    final_db_path = join(db_path, 'msd.db')
    if key_path and db_path and not key_path == r"HINT: D:\New Folder\msd\key.txt" and not db_path == r"HINT: E:\Data\Work\msd" and exists(db_path) and exists(key_path):

        if isfile(key_path):
            if not basename(key_path).split('.')[1] == 'txt': showerror("Error", "Not the required file")
        else: showerror("Error", "Invalid File")

        if not check_db():
            try:
                con = connect('data.db')
                cur = con.cursor()               
                cur.execute("INSERT INTO paths (pathname, path) VALUES (?,?)", ("key_path", b64encode(bytes(str(key_path), encoding='ISO-8859-1'))))
                cur.execute("INSERT INTO paths (pathname, path) VALUES (?,?)", ("db_path", b64encode(bytes(str(final_db_path), encoding='ISO-8859-1'))))
                con.commit()
                cur.close()
                con.close()
                message.set("Database is created and paths are saved successfully\n Close this window")
                key_entry["state"] = "disabled"
                db_entry["state"] = "disabled"
                validate_button["state"] = "disabled"
            except Exception as e: showerror("Error", "{}".format(e))      
    else:
        message.set("ERROR! occured in the given paths")
    
def secret():
    root = Tk()
    root.title("MSD - Validation")
    root.geometry("360x220")
    root.resizable(0, 0)
    key_label = Label(root, text='Enter the generated "KEY" path', font="16")
    key_entry_hint = StringVar()
    key_entry_hint.set(r"HINT: D:\New Folder\msd\key.txt")
    global key_entry
    key_entry = Entry(root, textvariable=key_entry_hint, width='50')
    key_gen_button = Button(root, text="Don't have a key create one!", command=open_key_gen)
    db_label = Label(root, text='Enter a vaild path to "SAVE" your Data', font='16')
    db_entry_hint = StringVar()
    db_entry_hint.set(r"HINT: E:\Data\Work\msd")
    global db_entry
    db_entry = Entry(root, textvariable=db_entry_hint, width='50')
    key_label.pack(pady=5)
    key_entry.pack(pady=5)
    key_gen_button.pack()
    db_label.pack(pady=5)
    db_entry.pack()
    global validate_button
    validate_button = Button(root, text='Validate', command=lambda: validate_paths(key_entry.get().strip(), db_entry.get().strip()))
    validate_button.pack(pady=5)
    global message
    message = StringVar()
    message.set("Clear the fields before writing your paths\n Do not close this window")
    message_label = Label(root, textvariable=message, fg='red')
    message_label.pack(pady=3)
    root.mainloop()

if __name__ == '__main__':
    print("This script should not be called directly!")
