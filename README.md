# Music Copyright Management System

## 1. Introduction

This application is created and ran in python script - **music_copyright.py**. It is a secure platform that allows users and administrator to create, read, update and delete their artifacts (including documents and audio files) via a command-line-interface. This application also implemented important security measures to protect sensitive data as well as to prevent common and serious security vulnerabilities.
  
This application also comes with 2 additional items below:

- A database - **music_database.db**, which stores the data related to the application.

- A log file – **access.log**, which records all activities taken in the application.


## 2. Security Features

*   **AES-256 Encryption (using `cryptography` library):**

    Once a document or an audio file (e.g. mp3) is uploaded to the application, the system uses Advanced Encryption Standard (AES) with 256-bit key to encrypt the artifact, or short for AES-256. And it will use the same method to decrypt the artifact once it is requested for retrieval.

    The AES algorithm is highly secure, flexible to use and it is approved by reputable government agency National Institute of Standards and Technology (NIST) under U.S. Department of Commerce. (NIST, 2001)
    
    *Justification:* The cryptography library is used in the application because it offers the ability to use AES encryption along with other cryptographic algorithms that provides strong protection for data in the application. This method offers a robust and effective encryption algorithm to secure sensitive information and resist to potential cryptanalytic attacks.

   
*   **Password Hashing (using `bcrypt` library):**
 
    Passwords are important credential information and must be protected, which is why bcrypt library is used to hash the password. This library also add salt to protect common attacks such as brute-force attacks.

    According to (Provos and Mazieres, 1999), the bcrypt method offers adaptable, secure in design and flexible in terms of computationl cost. 
    
    *Justification:* bcrypt is designed specifically for password hashing. It is an effective method to withstand brute-force attacks and it is a highly recommended security features in a lot of application.


    
*   **Input Sanitization (using `re` module):**
  
    According to OWASP Top 10, injection attacks rank the third in the top 10 list, which is why it indicates that SQL injection and cross-site scripting (XSS) are dangerous vulnerabilities and require robust security measures to prevent them. (OWASP, 2021) 

    The application has implemented input sanitization mechanism in order to prevent injection attacks such as SQL injection and Coss-site scripting (XSS). While a user is providing a file name or audio file, the input is validated to remove potentially characters or malicious code.
    
    *Justification:* By using the regular expression library (i.e. `re`), the system has the ability to pre-define acceptable patterns from user’s input. More importantly, it can identify and remove potentially malicious input of codes such as malicious sql  (" or 1=1). Properly implemented input validation is a fundamental security practice [6].

## 3. Installation

### Prerequisites

*   Python 3.6 or higher

### Windows

1.  Open a command prompt by searching "cmd" in the Start menu.
2.  Navigate to the directory where the `music_copyright.py` script is stored by using the `cd` command.
3.  Run the command below to install the required Python packages:

    ```
    pip install cryptography bcrypt
    ```

### macOS

1.  Open a terminal by searching "Terminal" in the Spotlight.
2.  Navigate to the directory where the `music_copyright.py` script is stored by using the `cd` command.
3.  Run the command below to install the required Python packages:

    ```
    pip3 install cryptography bcrypt
    ```


## 4. Usage

1.  **Save the Script:** Save the provided Python script (`music_copyright.py`) to a directory on your computer.
2.  **Run the Script:**

    *   Open a command prompt (Windows) or terminal (macOS).
    *   Navigate to the directory where the pytho script is stored by using the `cd` command.
    *   Run the script using the command below:

        ```
        python music_copyright.py
        ```

3.  **Follow the Prompts:** The script will guide you through a menu-driven interface to register users, log in, add documents/audio files, retrieve them, and perform other management tasks.

## 5. Functions Rundown
*Login page*
1.	**Register:** Register an account in order to login and conduct different action such as create & update artifacts.
2.	**Login:** Login as administrator or a registered account	

  	Default administrator credential is (Username: amdin1; Password: qwerty)
  	
  	**IMPORTANT REMINDER**: Please change the default password **IMMEIDATELY** after you logged in as an administrator the first time.
  	
4.	**Exit:** Exit the application

    <img width="657" alt="Screenshot 2025-03-05 at 23 01 36" src="https://github.com/user-attachments/assets/e9e90dfd-3142-4d51-9593-3e417a40590b" />

      **Figure 1: Login Page**

      <img width="657" alt="Screenshot 2025-03-05 at 23 01 57" src="https://github.com/user-attachments/assets/2cc015d0-9dab-4261-985e-caca0fbb5944" />
   
      **Figure 2: Logged in as an administrator**
   
      <img width="555" alt="Screenshot 2025-03-05 at 23 14 42" src="https://github.com/user-attachments/assets/fb31e277-af15-427a-a9d3-7d29e846106d" />
   
      **Figure 3: Logged in as an user**

*Main menu*

**Function 1 & 2: Add Document/audio files**

   In Figure 4, a test document named *test.docx* was uploaded into the application.
   
   The steps to take are follows:
   
   1.	Select a process ("Add Document") to run, so type "1" and hit enter.
   2.	Enter the file path.
   3.	Enter the administrator password.

   <img width="614" alt="Screenshot 2025-03-05 at 23 05 46 mod" src="https://github.com/user-attachments/assets/04e472b8-0761-48d3-8faa-e7fa02fffed1" />

   Figure 4: Uploading document in the application


**Function 3 & 4: Retrieve Document/audio files**

   In Figure 5, a test audio file named *test.mp3* was downloaded from the application.
   
   The steps to take are follows:
   
   1.	Select a process ("Retrieve Audio File") to run, so type "4" and hit enter.
   2.	Enter audio file ID.
   3.	Enter the administrator password.

   <img width="730" alt="Screenshot 2025-03-06 at 01 43 36" src="https://github.com/user-attachments/assets/5e1e42ab-5f0b-447c-a179-7ecab95520fc" />

   Figure 5: Retrieveing document from the application

## 6. Database
### 1. Access the database

Once you logged into the application, a database is generated. It is called music_database.db and it will be generated in the same directory as the python script.

To access and view the database, enter below command in the terminal.

        sqlite3 music_database.db

An additional command was provded to the database, which is ".tables". This will display the tables inside the *music_database.db. 
<img width="687" alt="Screenshot 2025-03-06 at 01 52 53" src="https://github.com/user-attachments/assets/d4e46f04-48c2-460e-b40e-e688dd92c83d" />

### 2. Table: Users
      select * from users;
Above SQL query will display the data in the user table, which consists of an administrator account (admin1) and a registered account (user).

<img width="959" alt="Screenshot 2025-03-05 at 23 17 44" src="https://github.com/user-attachments/assets/b0c8dd6a-9b70-44c6-b1bc-9c8631ba959a" />

### 3. Table: audio_files
      select * from audio_files;
Above SQL query will display the data in the artifact table, which consists of audio file (test.mp3).

<img width="1232" alt="Screenshot 2025-03-05 at 23 07 25" src="https://github.com/user-attachments/assets/1a2a8b87-9465-455a-bed7-ccca7b030b7c" />

### 4. Table: documents
      select * from documents;
Above SQL query will display the data in the document table, which consists of document (test.docx).

<img width="1273" alt="Screenshot 2025-03-06 at 02 10 05" src="https://github.com/user-attachments/assets/d78f4fef-f9ba-4575-869c-942d65f6bffc" />

## 7. Logging
### 1. Access the log file

Once you logged into the application, a log file is generated. It is called access.log and it will be generated in the same directory as the python script.

In the log file, it logs any activities conducted in the application and including information of date, time, what kind of activitiy and who conducted it.

To access and view the log, enter below command in the terminal.

      cat access.log

In figure 6 below, a lot of activities are logged into the file such as Audio file test.mp3 was successfully retrieved at 23:08pm on 5th Mar 2025.

   <img width="741" alt="Screenshot 2025-03-05 at 23 18 30 mod" src="https://github.com/user-attachments/assets/7d36a854-0337-477d-85c3-0d9ef46970a6" />

   Figure 6: Log files contains all activities conducted in the application.

## Core Functions Explanation

*   **`encrypt(data, password)`:** This function uses AES-256 to encrypt artifacts data (documents and audio files). The  ` encrypt ` function is called when a user wants to upload documents or audio files.
*   **`decrypt(encrypted_data, password)`:** This function decrypts the encrypted data using the same AES-256 method. The  ` decrypt ` function is called when a user wants to retrieve documents or audio files.
*   **`register_user()`:** This function registers a new user. It uses the `bcrypt` library to hash the input password and store it in the database.
*   **`login_user()`:** This function authenticates a user by comparing the input password with hashed password in the database.
*   **`validate_filename(filename)` and `validate_username(username)`:** These functions use regular expressions (`re` library)to validate filenames and usernames, preventing invalid or potentially malicious inputs.
*   **`log_activity(activity, username)`:** This function logs user activity to an "access.log" file. This log file can be used for important purposes including security audits and incident investigation/troubleshooting.

## Security Testing (Bandit)

This application has been tested with security testing tool - Bandit.

The figure below illustrates that the python script (i.e. music_copyright.py) has identified no severe security issues.

![Screenshot 2025-03-06 at 15 21 39](https://github.com/user-attachments/assets/41b2a8f5-1e96-4134-b534-3ed35a339b24)


## Academic References

National Institute of Standards and Technology (NIST). (2001). *Advanced Encryption Standard (AES)*. FIPS PUB 197. Available from: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf. [Accessed on 7th Mar 2025]

OWASP. (2021). OWASP Top Ten. Available from: https://owasp.org/www-project-top-ten/ [Accessed on 7th Mar 2025]

Provos, N., & Mazières, D. (1999). *A Future-Adaptable Password Scheme*. Available from: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf  [Accessed on 7th Mar 2025]
