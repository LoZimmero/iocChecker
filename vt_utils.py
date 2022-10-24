from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service

import tkinter as tk

root = tk.Tk()
root.withdraw()  # to hide the window


TEMP_MAIL_URL = 'https://temp-mail.org/it/'
VT_SIGNUP_PAGE = 'https://www.virustotal.com/gui/join-us'
PASSWORD = 'SamueleLuigi1!'

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

driver.get(TEMP_MAIL_URL)
driver.implicitly_wait(15) # seconds
email_elem = driver.find_element(By.XPATH, "//button[@id='click-to-copy']")
email_elem.click()
email_address = root.clipboard_get()             # fake email_address

print("EMAIL FOUND:", email_address)

# open new tab to open VT signup
driver2 = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver2.get(VT_SIGNUP_PAGE)

driver2.implicitly_wait(5)

# first_name
firstname_elem = driver2.find_element(By.XPATH, "//input[@placeholder=\"Enter your first name\"]")
firstname_elem.send_keys(email_address.split('@')[0])

# last_name
last_name_elem = driver2.find_element(By.XPATH, "//input[@placeholder='Enter your last name']")
last_name_elem.send_keys(email_address.split('@')[0])

# email
email_elem = driver2.find_element(By.XPATH, "//input[@placeholder=\"Enter your email address\"]")
email_elem.send_keys(email_address)

# username
username_elem = driver2.find_element(By.XPATH, "//input[@placeholder='Enter a username']")
username_elem.send_keys(email_address.split('@')[0])

# password
username_elem = driver2.find_element(By.XPATH, "//input[@placeholder='Min. 8 characters']")
username_elem.send_keys(PASSWORD)

driver2.implicitly_wait(10)

# check ok permissions
permissions = driver2.find_element(By.XPATH, "//input[@id='checkboxContainer']").click()


"""
elem = driver.find_element(By.NAME, "q")
elem.clear()
elem.send_keys("pycon")
elem.send_keys(Keys.RETURN)
"""
driver.close()