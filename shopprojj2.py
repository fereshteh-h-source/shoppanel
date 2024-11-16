import re
import sqlite3
import tkinter as tk
import json

cnt = sqlite3.connect('myshop.db')
# sql='''CREATE TABLE products(
#     id  INTEGER PRIMARY KEY,
#     name VARCHAR(40) NOT NULL,
#     price INTEGER NOT NULL,
#     quantity INTEGER NOT NULL
# )'''
# cnt.execute(sql)

# sql=''' INSERT INTO products (name,price,quantity)
#     VALUES("Del Laptop model C0021",21000,160)
#    '''
# cnt.execute(sql)
# cnt.commit()

# sql='''CREATE TABLE cart(
#      id  INTEGER PRIMARY KEY,
#    pid INTEGER NOT NULL,
#      uid INTEGER NOT NULL,
#     number INTEGER NOT NULL
#  )'''
# cnt.execute(sql)


def get_userset():
    Settings = json_file()
    ID = getId(txtUser.get())
    sql = f'''SELECT grade FROM users WHERE id={ID}'''
    result = ((cnt.execute(sql)).fetchall())[0][0]

    for k, v in sorted(Settings["usersettings"].items(), key=lambda x: int(x[0]), reverse=True):
        if result >= int(k):
            return v["shop"], v["my cart"]

    return 0, 0

from tkinter import messagebox
def mycart():
    def ok():
        winMycart.destroy()

    DCT = {}

    user_input = txtUser.get()
    ID = getId(user_input)

    if ID is None:
        messagebox.showerror("User Not Found", "No user found with the provided ID.")
        return

    sql = f'''SELECT c.pid, c.number, p.name FROM cart c 
              JOIN products p ON c.pid = p.id 
              WHERE c.uid = {ID}'''
    lst = cnt.execute(sql).fetchall()

    for item in lst:
        pid = str(item[0])
        number = item[1]
        product_name = item[2]
        if pid in DCT:
            DCT[pid]['quantity'] += number
        else:
            DCT[pid] = {'name': product_name, 'quantity': number}

    winMycart = tk.Toplevel(win)
    winMycart.title("My Cart:")
    winMycart.geometry("400x400")

    listbox = tk.Listbox(winMycart, width=50, height=15)
    listbox.pack(pady=10)

    for data in DCT.values():
        listbox.insert(tk.END, f"{data['name']} --------------- {data['quantity']}")
    tk.Button(winMycart, text="Ok", command=ok).pack(pady=10)
    winMycart.mainloop()
def getId(user):
    sql = f'''SELECT id FROM users WHERE username="{user}"'''
    result = cnt.execute(sql)
    rows = result.fetchall()
    return rows[0][0] if rows else None
def checkLogin(user, pas):
    try:
        sql = f'SELECT * FROM users WHERE username="{user}" AND password="{pas}"'
        result = cnt.execute(sql)
        return len(result.fetchall()) > 0
    except Exception as e:
        print(f"Error checking login: {e}")
        return False
def show_error_message(message, win):
    error_win = tk.Toplevel(win)
    error_win.title("Error")
    error_win.geometry("300x150")

    tk.Label(error_win, text=message).pack(pady=20)
    def close_error_win():
        error_win.destroy()

    btnOk = tk.Button(error_win, text="Ok", command=close_error_win)
    btnOk.pack(pady=10)

    error_win.mainloop()


def update_user_grade(MCM, win):
    mcm_value = MCM.get()
    if mcm_value == "":
        show_error_message("Empty Field!", win)
        return

    try:
        mcm = int(mcm_value)
        if mcm <= 0:
            raise ValueError("Grade must be greater than 0.")
        else:
            dct = json_file()
            dct["usergradebase"] = [mcm]
            with open("Settings.json", "w") as f:
                json.dump(dct, f)
            gradebox.configure(text=f"{json_file()}")


    except ValueError as e:
        show_error_message(f"Invalid Input: {e}", win)

def grade_counting_box(win):
    global gradebox
    tk.Label(win, text="Set user grade counting base (Leave empty if you don't want to change.):").pack()
    MCM = tk.Entry(win)
    MCM.pack()
    tk.Button(win, text="Set", command=lambda: update_user_grade(MCM, win)).pack()
    gradebox=tk.Label(win,text=f"{json_file()}")
    gradebox.pack()
def login():
    global session
    user, pas = txtUser.get(), txtPass.get()
    try:
        if checkLogin(user, pas):
            session = user
            lblMsg.configure(text='Welcome to your account!', fg='green')
            for widget in (txtUser, txtPass, btnLogin, btnSignup):
                widget.configure(state='disabled')
            if user != "admin":
                a,b=get_userset()
                if a==1:
                    tk.Button(win, text='Shop Panel', command=shopPanel).pack()
                if b==1:
                    tk.Button(win, text="My Cart", command=mycart).pack()
            if user == "admin":
                tk.Button(win, text="Users Setting", command=Userssettings).pack(pady=5)
                tk.Button(win, text="Products Setting", command=Productssettings).pack(pady=5)
                tk.Button(win, text="Add Product", command=insertnewproducts).pack(pady=5)
                grade_counting_box(win)
        else:
            lblMsg.configure(text='Wrong username or password!', fg='red')
    except Exception as e:
        lblMsg.configure(text='An error occurred: {}'.format(str(e)), fg='red')
def signup():
    def signupValidate(user, pas, cpas, addr):
        if not all([user, pas, cpas, addr]):
            return False, 'Empty fields error!'
        if pas != cpas:
            return False, 'Password and confirmation mismatch!'
        if len(pas) < 8:
            return False, 'Password must be at least 8 chars!'
        if cnt.execute(f'SELECT * FROM users WHERE username="{user}"').fetchall():
            return False, 'Username already exists!'
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$", pas):
            return False, 'Password must have at least one uppercase letter, one lowercase letter, and one number.'
        return True, ''

    def save2users(user, pas, addr):
        try:
            sql = f'INSERT INTO users (username, password, address, grade) VALUES ("{user}", "{pas}", "{addr}", 5)'
            cnt.execute(sql)
            cnt.commit()
            return True
        except Exception as e:
            print(f"Error saving user: {e}")
            return False

    def submit():
        user, pas, cpas, addr = txtUser2.get(), txtPass2.get(), txtcPass2.get(), txtaddr.get()
        result, errormsg = signupValidate(user, pas, cpas, addr)
        if not result:
            lblMsg2.configure(text=errormsg, fg="red")
            return
        if save2users(user, pas, addr):
            lblMsg2.configure(text='Submit done successfully!\nYou have reached Grade 5!\nQuit to login!', fg='green')
            for field in (txtUser2, txtPass2, txtcPass2, txtaddr):
                field.delete(0, 'end')
        else:
            lblMsg2.configure(text='Error while connecting to database!', fg='red')
    winSignup = tk.Toplevel(win)
    winSignup.title('Signup Panel')
    winSignup.geometry('400x400')
    lblUser2 = tk.Label(winSignup, text='Username: ')
    lblUser2.pack()
    txtUser2 = tk.Entry(winSignup)
    txtUser2.pack()
    lblPass2 = tk.Label(winSignup, text='Password: ')
    lblPass2.pack()
    txtPass2 = tk.Entry(winSignup, show='*')
    txtPass2.pack()
    lblcPass2 = tk.Label(winSignup, text='Password confirmation: ')
    lblcPass2.pack()
    txtcPass2 = tk.Entry(winSignup, show='*')
    txtcPass2.pack()
    lbladdr = tk.Label(winSignup, text='Address: ')
    lbladdr.pack()
    txtaddr = tk.Entry(winSignup)
    txtaddr.pack()
    lblMsg2 = tk.Label(winSignup, text='')
    lblMsg2.pack()
    btnSubmit = tk.Button(winSignup, text='Submit', command=submit)
    btnSubmit.pack()
    winSignup.mainloop()


def getProducts():
    return cnt.execute('SELECT * FROM products').fetchall()

def updateQNT(pid, pnumber):

    try:
        sql = '''UPDATE products SET quantity = quantity - ? WHERE id = ? AND quantity >= ?'''
        cursor = cnt.cursor()  # گرفتن شی cursor
        cursor.execute(sql, (int(pnumber), int(pid), int(pnumber)))
        if cursor.rowcount == 0:
            raise ValueError("Not enough stock or product ID not found.")

        cnt.commit()
    except Exception as e:
        cnt.rollback()
        print(f"Error while updating quantity: {str(e)}")
def shopPanel():
    def shopValidate(pid, pnumber):
        if not pid.isdigit() or not pnumber.isdigit():
            if pid == "" or pnumber == "":
                return False, 'Empty fields!'
            else:
                return False, 'Invalid input!'

        sql = '''SELECT * FROM products WHERE id=?'''
        result = cnt.execute(sql, (int(pid),)).fetchone()
        if not result:
            return False, 'Wrong product id!'
        sql = '''SELECT * FROM products WHERE id=? AND quantity>=?'''
        result = cnt.execute(sql, (int(pid), int(pnumber))).fetchone()
        if not result:
            return False, 'Not enough products!'

        return True, ''

    def save2cart():
        global session
        pid = txtId.get()
        pnumber = txtnum.get()

        result, msg = shopValidate(pid, pnumber)
        lblMsg3.configure(text=msg, fg='red' if not result else 'green')# آیا خرید موفق بود یا نه
        if not result:
            return

        try:
            updateQNT(pid, pnumber)
            uid = getId(session)
            sql = '''INSERT INTO cart (pid, uid, number) VALUES (?, ?, ?)'''
            cnt.execute(sql, (int(pid), uid, int(pnumber)))
            cnt.commit()

            lblMsg3.configure(text="Saved to your cart!", fg="green")
            txtId.delete(0, "end")
            txtnum.delete(0, "end")
            showProducts(getProducts())
            new_cart_items = [(int(pid), int(pnumber))]
            totalpayment(new_cart_items)

        except Exception as e:
            cnt.rollback()
            lblMsg3.configure(text=f"Error: {str(e)}", fg="red")

    def showProducts(products):
        lstbox.delete(0, "end")
        for product in products:
            text = f'Id={product[0]}  Name={product[1]}  Price={product[2]}   QNT={product[3]}'
            lstbox.insert('end', text)
    winShop = tk.Toplevel(win)
    winShop.title('Shop Panel')
    winShop.geometry('400x400')
    lstbox = tk.Listbox(winShop, width=80)
    lstbox.pack(pady=10)
    lblId = tk.Label(winShop, text='Product Id:')
    lblId.pack()
    txtId = tk.Entry(winShop)
    txtId.pack(pady=5)
    lblnum = tk.Label(winShop, text='Quantity:')
    lblnum.pack()
    txtnum = tk.Entry(winShop)
    txtnum.pack(pady=5)
    lblMsg3 = tk.Label(winShop, text='')
    lblMsg3.pack()
    btnBuy = tk.Button(winShop, text='Add to Cart', command=save2cart)
    btnBuy.pack(pady=10)
    showProducts(getProducts())
    winShop.mainloop()
def Userssettings():
    winAd = tk.Toplevel(win)
    winAd.title("Update User Info Panel")
    winAd.geometry("500x400")

    tk.Label(winAd, text="User ID:").pack()
    txtuserSet1 = tk.Entry(winAd)
    txtuserSet1.pack()

    tk.Label(winAd, text="New Username (leave empty if no change):").pack()
    txtuserSet2 = tk.Entry(winAd)
    txtuserSet2.pack()

    tk.Label(winAd, text="New Password (leave empty if no change):").pack()
    txtuserSet3 = tk.Entry(winAd, show='*')
    txtuserSet3.pack()

    tk.Label(winAd, text="New Address (leave empty if no change):").pack()
    txtuserSet4 = tk.Entry(winAd)
    txtuserSet4.pack()

    tk.Label(winAd, text="New Grade (leave empty if no change):").pack()
    txtuserSet5 = tk.Entry(winAd)
    txtuserSet5.pack()

    lblMssg = tk.Label(winAd, text="")
    lblMssg.pack()

    def userinfoprocessing():
        global textuserSet1, original_values
        textuserSet1 = txtuserSet1.get()
        if not textuserSet1:
            lblMssg.configure(text="Please enter a User ID!", fg="red")
            return

        try:
            sql = f'SELECT username, password, address, grade FROM users WHERE id={int(textuserSet1)}'
            result = cnt.execute(sql)
            lst = result.fetchall()
            if not lst:
                lblMssg.configure(text="ID not found!", fg="red")
                return
            original_values = dict(zip(["username", "password", "address", "grade"], lst[0]))
            lblMssg.configure(text=f"User's Username is {original_values['username']}.", fg="green")
            new_username = txtuserSet2.get()
            new_password = txtuserSet3.get()
            new_address = txtuserSet4.get()
            try:
                new_grade = int(txtuserSet5.get()) if txtuserSet5.get() else None
            except ValueError:
                new_grade = None
            if new_username and new_username != original_values["username"]:
                existing_user_id = getId(new_username)
                if existing_user_id:
                    lblMssg.configure(text="This username is already taken. Please choose another one.", fg="red")
                    return
            if (new_username == original_values["username"] or new_username == "") and \
                    (new_password == original_values["password"] or new_password == "") and \
                    (new_address == original_values["address"] or new_address == "") and \
                    (new_grade == original_values["grade"] or new_grade is None):
                winWrong = tk.Toplevel(winAd)
                winWrong.geometry("300x300")
                winWrong.title("Something went wrong!")
                tk.Label(winWrong, text="No Alteration! Please change at least one property!").pack()
                tk.Button(winWrong, text="OK", command=winWrong.destroy).pack()
            elif (new_username == original_values["username"]) or \
                    (new_password == original_values["password"]) or \
                    (new_address == original_values["address"]) or \
                    (new_grade == original_values["grade"]):
                winWrong = tk.Toplevel(winAd)
                winWrong.geometry("200x200")
                winWrong.title("Something went wrong!")
                tk.Label(winWrong, text="Leave empty if you don't want to change!").pack()
                tk.Button(winWrong, text="OK", command=winWrong.destroy).pack()

            else:
                global winConfirmupdate
                winConfirmupdate = tk.Toplevel(winAd)
                winConfirmupdate.geometry("200x200")
                winConfirmupdate.title("Confirm Panel")
                tk.Label(winConfirmupdate, text=f"User's Username is ({original_values["username"]}.)\nAre you sure about Updating\nthis User's Info?").pack()
                tk.Button(winConfirmupdate, text="Yes", command=userinfoupdate).pack()
                tk.Button(winConfirmupdate, text="No", command=winConfirmupdate.destroy).pack()

        except Exception as e:
            lblMssg.configure(text=f"Error fetching user info: {e}", fg="red")

    def userinfoupdate():
        try:
            updates = {
                "username": txtuserSet2.get(),
                "password": txtuserSet3.get(),
                "address": txtuserSet4.get(),
            }
            grade = int(txtuserSet5.get())
            for column, new_value in updates.items():
                if new_value and new_value != original_values[column]:
                    sql = f'UPDATE users SET {column}="{new_value}" WHERE id={int(textuserSet1)}'
                    cnt.execute(sql)
            sql = f'UPDATE users SET grade={grade} WHERE id={int(textuserSet1)}'
            cnt.execute(sql)
            cnt.commit()
            winConfirmupdate.destroy()

        except Exception as e:
            lblMssg.configure(text=f"Error updating user info: {e}", fg="red")

    def deleteuseraccount():
        textuserSet1 = txtuserSet1.get()
        sql=f'''SELECT username FROM users WHERE id={int(textuserSet1)}'''
        US=((cnt.execute(sql)).fetchall())[0][0]

        def confirm_delete():
            try:
                sql = f'''DELETE FROM users WHERE id={int(textuserSet1)}'''
                cnt.execute(sql)
                cnt.commit()
                winCondelete.destroy()
                lblMssg.configure(text="User deleted successfully!", fg="green")
            except Exception as e:
                lblMssg.configure(text=f"Error deleting user: {e}", fg="red")

        def cancel_delete():
            winCondelete.destroy()

        global winCondelete
        winCondelete = tk.Toplevel(winAd)
        winCondelete.title("Delete Process Confirm")
        winCondelete.geometry("300x300")
        tk.Label(winCondelete, text=f"User's Id is {US}.\nAre you sure about deleting this User's Account?").pack()
        tk.Button(winCondelete, text="Yes", command=confirm_delete).pack()
        tk.Button(winCondelete, text="No", command=cancel_delete).pack()
        winCondelete.mainloop()

    tk.Button(winAd, text="Submit", command=userinfoprocessing).pack()
    tk.Button(winAd, text="Delete User's Account", command=deleteuseraccount).pack()

    winAd.mainloop()
def Productssettings():
    winAd = tk.Toplevel(win)
    winAd.title("Update Product Info Panel")
    winAd.geometry("400x400")
    tk.Label(winAd, text="Product ID:").pack()
    txtProductSet1 = tk.Entry(winAd)
    txtProductSet1.pack()

    tk.Label(winAd, text="New Price (leave empty if no change):").pack()
    txtProductSet2 = tk.Entry(winAd)
    txtProductSet2.pack()

    tk.Label(winAd, text="New Quantity (leave empty if no change):").pack()
    txtProductSet3 = tk.Entry(winAd)
    txtProductSet3.pack()

    lblMssg = tk.Label(winAd, text="")
    lblMssg.pack()

    def validate_and_convert_input():
        try:
            new_price = txtProductSet2.get()
            if new_price:
                new_price = float(new_price)
            else:
                new_price = None

            new_quantity = txtProductSet3.get()
            if new_quantity:
                new_quantity = int(new_quantity)
            else:
                new_quantity = None

            return new_price, new_quantity
        except ValueError:
            lblMssg.configure(text="Invalid input! Please enter valid numbers for Price and Quantity.", fg="red")
            return None, None
    def productInfoProcessing():
        product_id = txtProductSet1.get()

        if not product_id:
            lblMssg.configure(text="Please enter a Product ID!", fg="red")
            return

        try:
            sql = "SELECT name, price, quantity FROM products WHERE id = ?"
            result = cnt.execute(sql, (product_id,))
            lst = result.fetchall()

            if not lst:
                lblMssg.configure(text="Product ID not found!", fg="red")
                return

            original_values = dict(zip(["name", "price", "quantity"], lst[0]))
            lblMssg.configure(text=f"Product Name is {original_values['name']}.", fg="green")
            new_price, new_quantity = validate_and_convert_input()

            if new_price is None and new_quantity is None:
                return
            changes_made = False
            if new_price is not None and new_price != original_values["price"]:
                changes_made = True
            if new_quantity is not None and new_quantity != original_values["quantity"]:
                changes_made = True

            if not changes_made:
                messagebox.showinfo("No Changes", "Please change at least one field.")
            else:
                confirm_update = messagebox.askyesno("Confirm Update",
                                                     f"Product's Name is ({original_values['name']}).\nAre you sure about updating this product's info?")
                if confirm_update:
                    productInfoUpdate(new_price, new_quantity, product_id, original_values)

        except Exception as e:
            lblMssg.configure(text=f"Error fetching product info: {e}", fg="red")
    def productInfoUpdate(new_price, new_quantity, product_id, original_values):
        try:
            updates = {}
            if new_price is not None:
                updates["price"] = new_price
            if new_quantity is not None:
                updates["quantity"] = new_quantity

            for column, new_value in updates.items():
                if new_value != original_values[column]:
                    sql = f"UPDATE products SET {column} = ? WHERE id = ?"
                    cnt.execute(sql, (new_value, product_id))

            cnt.commit()
            lblMssg.configure(text="Product info updated successfully!", fg="green")
        except Exception as e:
            lblMssg.configure(text=f"Error updating product info: {e}", fg="red")
    def deleteProduct():
        product_id = txtProductSet1.get()
        sql = f"SELECT name FROM products WHERE id = ?"
        result = cnt.execute(sql, (product_id,))
        lst = result.fetchall()

        if not lst:
            lblMssg.configure(text="Product ID not found!", fg="red")
        else:
            product_name = lst[0][0]
            confirm_delete = messagebox.askyesno("Confirm Delete",
                                                 f"Product's Name is {product_name}.\nAre you sure about deleting this product?")
            if confirm_delete:
                try:
                    sql = f"DELETE FROM products WHERE id = ?"
                    cnt.execute(sql, (product_id,))
                    cnt.commit()
                    lblMssg.configure(text="Product deleted successfully!", fg="green")
                except Exception as e:
                    lblMssg.configure(text=f"Error deleting product: {e}", fg="red")
    tk.Button(winAd, text="Submit", command=productInfoProcessing).pack()
    tk.Button(winAd, text="Delete Product", command=deleteProduct).pack()


    winAd.mainloop()

def totalpayment(new_cart_items):
    global session
    try:
        grade_threshold = (json_file())["usergaradebase"][0]
    except KeyError:
        show_error_message("Error reading grade threshold from JSON.", win)
        return
    ID = getId(session)
    if not ID:
        show_error_message("User ID not found.", win)
        return
    product_ids_new = [item[0] for item in new_cart_items]
    sql_prices_new = '''SELECT id, price FROM products WHERE id IN ({})'''.format(
        ','.join(['?'] * len(product_ids_new)))
    result_prices_new = cnt.execute(sql_prices_new, tuple(product_ids_new))
    product_prices_new = dict(result_prices_new.fetchall())
    total_new_purchase = sum(product_prices_new.get(item[0], 0) * item[1] for item in new_cart_items)
    sql_grade = '''SELECT grade FROM users WHERE username = ?'''
    result_grade = cnt.execute(sql_grade, (session,))
    grade_data = result_grade.fetchone()
    if not grade_data:
        show_error_message("User grade not found.", win)
        return

    grade = grade_data[0]
    new_grade = grade + int(total_new_purchase / grade_threshold)
    if new_grade > 20:
        new_grade = 20

    if new_grade != grade:
        sql_update_grade = '''UPDATE users SET grade = ? WHERE username = ?'''
        cnt.execute(sql_update_grade, (new_grade, session))
        cnt.commit()
    cnt.commit()
from tkinter import messagebox
def insertnewproducts():
    def savetoproducts():
        product_name = p1.get()
        product_price = p2.get()
        product_quantity = p3.get()
        if not product_name or not product_price or not product_quantity:
            lbl4.configure(text="No field must be empty!", fg="red")
            return
        sql = '''SELECT id FROM products WHERE name = ?'''
        RES = cnt.execute(sql, (product_name,))
        if len(RES.fetchall()) > 0:
            lbl4.configure(text="This product already exists!", fg="red")
            return
        try:
            product_price = float(product_price)
            product_quantity = int(product_quantity)
        except ValueError:
            lbl4.configure(text="Price and Quantity must be valid numbers!", fg="red")
            return
        try:
            sql = '''INSERT INTO products (name, price, quantity) VALUES (?, ?, ?)'''
            cnt.execute(sql, (product_name, product_price, product_quantity))
            cnt.commit()
            lbl4.configure(text="Product added successfully!", fg="green")
            p1.delete(0, tk.END)
            p2.delete(0, tk.END)
            p3.delete(0, tk.END)

        except Exception as e:
            lbl4.configure(text=f"Error: {e}", fg="red")
    winaddnp = tk.Toplevel(win)
    winaddnp.geometry("400x400")
    winaddnp.title("Add New Product")
    lbl1 = tk.Label(winaddnp, text="Product Name:")
    lbl1.pack()
    p1 = tk.Entry(winaddnp)
    p1.pack()
    lbl2 = tk.Label(winaddnp, text="Product Price:")
    lbl2.pack()
    p2 = tk.Entry(winaddnp)
    p2.pack()
    lbl3 = tk.Label(winaddnp, text="Product Quantity:")
    lbl3.pack()
    p3 = tk.Entry(winaddnp)
    p3.pack()
    lbl4 = tk.Label(winaddnp, text="", fg="red")
    lbl4.pack()
    tk.Button(winaddnp, text="Add Product", command=savetoproducts).pack()
    winaddnp.mainloop()
def json_file():
    try:
        with open("Settings.json", "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}
win = tk.Tk()
win.title('Main Panel')
win.geometry("500x500")
tk.Label(win, text='Username: ').pack()
txtUser = tk.Entry(win)
txtUser.pack()
tk.Label(win, text='Password: ').pack()
txtPass = tk.Entry(win, show='*')
txtPass.pack()
lblMsg = tk.Label(win, text='')
lblMsg.pack()
btnLogin = tk.Button(win, text='Login', command=login)
btnLogin.pack()
btnSignup = tk.Button(win, text='Signup', command=signup)
btnSignup.pack()
win.mainloop()
