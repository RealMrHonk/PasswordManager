from datetime import datetime
import random
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
import json


class PasswordGenerator():

    lowerCase = "abcdefghijklmnopqrstuvwxyz"
    upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    decimal   = "0123456789"
    symbols   = "!#$%'()*+,-./:;<=>?@[]^_`{|}~"

    allCharacters = lowerCase + upperCase + decimal + symbols

    @staticmethod
    def GeneratePassword(passwordLength):
        password = []

        for x in range(passwordLength):
            password.append(PasswordGenerator.allCharacters[random.randrange(len(PasswordGenerator.allCharacters))])

        return "".join(password)

    @staticmethod
    def EncryptPassword(password, key):

        return Fernet(key).encrypt(password.encode()).decode() #Encode password str fot Encryption based on given key and return decoded str

    @staticmethod
    def DecryptPassword(encryptedPassword, key):

         
        try: 
            return (Fernet(key).decrypt(encryptedPassword.encode())).decode() 
        except: 
            return "Wrong key!"


    @staticmethod 
    def GenerateMasterKey():
        return Fernet.generate_key()

class FileHandler():

    lastLoadedPasswordList = ""
    lastLoadedMasterKey = ""

    @staticmethod
    def selectPath(type):
        if type == "json":
            filePath = filedialog.askopenfilename(initialdir="C:/user/documents/", title="Select a Password list", filetypes=(("Password lists", "*.json"),("All", "*.*")))
        elif type == "key":
            filePath = filedialog.askopenfilename(initialdir="C:/user/documents/", title="Select a key file", filetypes=(("Master-Key", "*.key"),("All", "*.*")))
        elif type =="folder":
            filePath = filedialog.askdirectory(initialdir="C:/user/documents/", title="Select a folder")
        else:
            print("Error wrong FileType")

        return filePath


    @staticmethod
    def LoadPasswordList():
        file = FileHandler.selectPath("json")
        if file:
            FileHandler.lastLoadedPasswordList = file
            passwordListJSON = open(file, "r")
            passwordList = json.load(passwordListJSON)
            passwordListJSON.close()

            return passwordList

    @staticmethod
    def CreatePasswordList(passwordList):
        file = FileHandler.selectPath("folder")+"/Password-List" + datetime.now().strftime("%m.%d.%Y %H-%M-%S") + ".json"
        FileHandler.lastLoadedPasswordList = file
        with open(file, "w") as json_file:
            json.dump(passwordList,json_file)

    @staticmethod
    def SavePasswordList(passwordList, file=None):
        if not file:
            file = FileHandler.lastLoadedPasswordList
        with open(file, "w") as json_file:
            json.dump(passwordList,json_file)

    @staticmethod
    def LaodMasterKey():
        file = FileHandler.selectPath("key")
        if file:
            FileHandler.lastLoadedMasterKey = file
            masterKeyFile = open(file, "r")
            masterKey = masterKeyFile.readline().encode()
            masterKeyFile.close()

            return masterKey

    @staticmethod 
    def SaveMasterKey(masterKey):
        file = FileHandler.selectPath("folder")+"/MasterKey " + datetime.now().strftime("%m.%d.%Y %H-%M-%S") + ".key"
        if file !="/MasterKey.key":
            with open(file, "w") as masterKeyFile:
                masterKeyFile.write(masterKey.decode())
                return TRUE
        else:
            return False

    @staticmethod
    def GetLastKeyName():
        splited = FileHandler.lastLoadedMasterKey.split("/")
        return splited[-1]

    @staticmethod 
    def GetLastPasswordListName():
        splited = FileHandler.lastLoadedPasswordList.split("/")
        return splited[-1]

class Application(Frame):

    def __init__(self, master=None):
        super().__init__(master)
        self.master = master

        self.currentKey = ""
        self.currentPasswordList = {}
        self.passwordTable = []

        self.currentKeyInfoText = StringVar()
        self.currentKeyInfoText.set("NONE")

        self.currentPasswordListInfoText = StringVar()
        self.currentPasswordListInfoText.set("NONE")

        self.errorInfoText = StringVar()

        self.create_widgets()
        self.update()

    def create_widgets(self):
        self.tab_Notebook = ttk.Notebook(self.master)

        self.passwordGenerationTab = ttk.Frame(self.tab_Notebook)
        self.passwordListTab = ttk.Frame(self.tab_Notebook)

        self.tab_Notebook.add(self.passwordGenerationTab, text='Password Creator')
        self.tab_Notebook.add(self.passwordListTab, text="Password List")

        #Info
        currentKeyInfoTitleLabel = Label(self.master, text="Key:")
        currentKeyInfoTitleLabel.place(rely=0.87, relheight=0.07)

        currentKeyInfoLabel = Label(self.master, textvariable=self.currentKeyInfoText)
        currentKeyInfoLabel.place(rely=0.92, relheight=0.07)


        currentPasswordListInfoTitleLabel = Label(self.master, text="Password list:")
        currentPasswordListInfoTitleLabel.place(relx=0.27, rely=0.87, relheight=0.07)

        currentPasswordListInfoLabel = Label(self.master, textvariable=self.currentPasswordListInfoText)
        currentPasswordListInfoLabel.place(relx=0.27, rely=0.92, relheight=0.07)

        #####  PasswordGenerationTab  #####

        #Error Info
        infoLabelPasswordGenerationTab = Label(self.passwordGenerationTab, textvariable=self.errorInfoText)
        infoLabelPasswordGenerationTab.place(relx=0.3, rely=0.2, relwidth=0.4, relheight=0.07)


        #Key Buttons
        self.chooseKeyButton = Button(self.passwordGenerationTab, text="Choose Key", command=self.addKey)
        self.chooseKeyButton.place(relx=0.3, rely=0.3, relwidth=0.175, relheight=0.07)

        self.generateKeyButton = Button(self.passwordGenerationTab, text="Creat Key", command=self.generateKey)
        self.generateKeyButton.place(relx=0.525, rely=0.3, relwidth=0.175, relheight=0.07)


        #Password Info
        self.passwordNameLabel = Label(self.passwordGenerationTab, text="Password Name")
        self.passwordNameLabel.place(relx=0.237, rely=0.43, relwidth=0.25, relheight=0.07)
        self.passwordNameEnrty = Entry(self.passwordGenerationTab)
        self.passwordNameEnrty.place(relx=0.3, rely=0.50, relwidth=0.25, relheight=0.07)

        self.passwordEntry = Entry(self.passwordGenerationTab)
        self.passwordEntry.place(relx=0.3, rely=0.60, relwidth=0.34, relheight=0.07)

        self.passwordLenghtEntry = Entry(self.passwordGenerationTab)
        self.passwordLenghtEntry.place(relx=0.65, rely=0.60, relwidth=0.05, relheight=0.07)

        #Password Buttons
        self.generatePasswordButton = Button(self.passwordGenerationTab, text="Generate Password", command=self.generatePassword)
        self.generatePasswordButton.place(relx=0.31, rely=0.7, relwidth=0.175, relheight=0.07)

        self.savePasswordButton = Button(self.passwordGenerationTab, text="Save Password", command=self.trySavePassword)
        self.savePasswordButton.place(relx=0.51, rely=0.7, relwidth=0.175, relheight=0.07)

        #####  PasswordListTab  #####

        #Error Info
        self.errorLabelPasswordListTab = Label(self.passwordListTab, textvariable=self.errorInfoText, wraplength=150, justify=LEFT)
        self.errorLabelPasswordListTab.place(relx= 0.55, rely=0.89, relwidth=0.2, relheight=0.1)

        #Password list Buttons
        self.choosePasswordListButton = Button(self.passwordListTab, text="Choose Passwordlist", width=25, command=self.addPasswordListToPasswordTable)
        self.choosePasswordListButton.place(rely=0.01, relwidth=0.5, relheight=0.065)

        self.addKeyButton = Button(self.passwordListTab, text="Choose Key", width=25, command=self.addKeyToPasswordTable)
        self.addKeyButton.place(relx= 0.5, rely=0.01, relwidth=0.5, relheight=0.065)


        self.savePasswordListChangesButton = Button(self.passwordListTab, text="Save Changes", width=25, command=self.savePasswordListChanges)
        self.savePasswordListChangesButton.place(relx= 0.77, rely=0.9, relwidth=0.2, relheight=0.07)

        self.tab_Notebook.place(relwidth=1.0, relheight=1.0)




    def addKey(self):
        self.currentKey = FileHandler.LaodMasterKey()
        if not self.currentKey:
            self.errorInfoText.set("No key selected!")
        else:
            self.creatPasswordTable() 
            self.currentKeyInfoText.set(FileHandler.GetLastKeyName())

    def generateKey(self):
        self.currentKey = PasswordGenerator.GenerateMasterKey()
        if not FileHandler.SaveMasterKey(self.currentKey):
            self.errorInfoText.set("Generated key couldnt be saved!")
        else:
            self.creatPasswordTable()
            self.currentKeyInfoText.set(FileHandler.GetLastKeyName())


    def generatePassword(self):   
        
        try:
            self.passwordEntry.delete(0,len(self.passwordEntry.get()))
            self.passwordEntry.insert(0,PasswordGenerator.GeneratePassword(int(self.passwordLenghtEntry.get())))

        except:
            self.passwordEntry.insert(0,"Please insert password length ->")
             

    def trySavePassword(self):
        if not self.passwordEntry.get():
            self.errorInfoText.set("No Password!")
        elif not self.currentKey:
            self.errorInfoText.set("No Key!")
        elif not self.passwordNameEnrty.get():
            self.errorInfoText.set("No Password Name!")
        else:

            win = Toplevel()
            win.title("Password List")
            win.maxsize(500,200)
            win.minsize(500,200)
            Label(win, text="Do you want to create a new list or use an existing one?").place(relx=0.1, rely=0.275, relwidth=0.8, relheight=0.3)
            Button(win, text="Existing", command=lambda: [self.savePasswordInExistingList(), win.destroy()]).place(relx=0.25, rely=0.75, relwidth=0.2, relheight=0.175)
            Button(win, text="Create", command=lambda: [self.savePasswordInNewList(), win.destroy()]).place(relx=0.5, rely=0.75, relwidth=0.2, relheight=0.175)
            Button(win, text="Cancel", command=win.destroy).place(relx=0.775, rely=0.75, relwidth=0.2, relheight=0.175)

    def savePasswordInNewList(self):
        self.currentPasswordList.clear()
        self.currentPasswordList.update({self.passwordNameEnrty.get() : PasswordGenerator.EncryptPassword(self.passwordEntry.get(),self.currentKey)})
        FileHandler.CreatePasswordList(self.currentPasswordList)
        self.creatPasswordTable()
        self.currentPasswordListInfoText.set(FileHandler.GetLastPasswordListName())

    def savePasswordInExistingList(self):
        self.currentPasswordList = FileHandler.LoadPasswordList()
        if self.currentPasswordList:
            if list(self.currentPasswordList).__contains__(self.passwordNameEnrty.get()):
                win = Toplevel()
                win.title("Password already exists")
                win.maxsize(500,200)
                win.minsize(500,200)
                Label(win, text="The password your tying to save already exists !\nDo You want to override or rename it ?").place(relx=0.1, rely=0.275, relwidth=0.8, relheight=0.3)
                Button(win, text="Override", command=lambda: [self.updateCurrentPasswordList(), win.destroy()]).place(relx=0.3, rely=0.72, relwidth=0.175, relheight=0.15)
                Button(win, text="Rename", command=win.destroy).place(relx=0.5, rely=0.72, relwidth=0.175, relheight=0.15)

            else:
                self.updateCurrentPasswordList()
                 
        else:
            self.errorInfoText.set("Password couldnt be saved!")
        

    def updateCurrentPasswordList(self):
        self.currentPasswordList.update({self.passwordNameEnrty.get() : PasswordGenerator.EncryptPassword(self.passwordEntry.get(),self.currentKey)})
        FileHandler.SavePasswordList(self.currentPasswordList)
        self.creatPasswordTable()
        self.currentPasswordListInfoText.set(FileHandler.GetLastPasswordListName())


    def creatPasswordTable(self):

        self.passwordTable.clear()

        canvasFrame = Frame(self.passwordListTab)
        canvasFrame.place(relx=0.02, rely= 0.1, relwidth=0.95, relheight=0.75)

        canvas = Canvas(canvasFrame)
        canvas.place(relwidth=1.0, relheight=1.0)

        scrollbar = Scrollbar(canvasFrame, command=canvas.yview)
        scrollbar.place(relx=0.97, relwidth=0.03, relheight=1.0)
        canvas.configure(yscrollcommand=scrollbar.set)

        tableFrame = Frame(canvas)
        canvas.create_window((0, 0), window=tableFrame, anchor='nw')

        for x in range(len(self.currentPasswordList)):
            passwordTableNameEntry = Entry(tableFrame, width = 17)
            passwordTableNameEntry.grid(row = x, column = 0)
            passwordTableNameEntry.insert(0, list(self.currentPasswordList)[x])

            passwordTablePasswordEntry = Entry(tableFrame, width=90)
            passwordTablePasswordEntry.grid(row = x, column = 1)
            if self.currentKey:
                passwordTablePasswordEntry.insert(0, PasswordGenerator.DecryptPassword(self.currentPasswordList[passwordTableNameEntry.get()], self.currentKey))
                self.passwordTable.append(passwordTableNameEntry)
                self.passwordTable.append(passwordTablePasswordEntry)
            else:
                passwordTablePasswordEntry.insert(0, self.currentPasswordList[list(self.currentPasswordList)[x]])

        tableFrame.update_idletasks()

        canvas.config(scrollregion=canvas.bbox("all"))

    def addPasswordListToPasswordTable(self):
        self.currentPasswordList = FileHandler.LoadPasswordList()
        if self.currentPasswordList:
            self.creatPasswordTable()
        self.currentPasswordListInfoText.set(FileHandler.GetLastPasswordListName())

    def addKeyToPasswordTable(self):
        self.addKey()
        if self.currentKey:
            self.creatPasswordTable()
        self.currentKeyInfoText.set(FileHandler.GetLastKeyName())
 
    def savePasswordListChanges(self):
        if messagebox.askokcancel("Save Changes","Are you sure you want to completly override\n" +  FileHandler.GetLastPasswordListName() + "?\nKey: " +  FileHandler.GetLastKeyName()):
            self.currentPasswordList.clear()
            for x in range(0,len(self.passwordTable),2):
                passwordName = self.passwordTable[x].get()
                password = self.passwordTable[x+1].get()

                if passwordName and password:
                    self.currentPasswordList.update({passwordName : PasswordGenerator.EncryptPassword(password, self.currentKey)})
            
            FileHandler.SavePasswordList(self.currentPasswordList,FileHandler.lastLoadedPasswordList)
            self.creatPasswordTable()


root = Tk()

root.title("Password Manager")
root.minsize(700,400)
root.maxsize(700,400)

root.grid_rowconfigure(0, weight=1)
root.columnconfigure(0, weight=1)

app = Application(master=root)

root.mainloop()
