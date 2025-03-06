# Music Copyright Management System

## 1. Introduction

This application is created and ran in python script - **music_copyright.py**. It is a secure platform that allows users and administrator to create, read, update and delete their artifacts (including documents and audio files) via a command-line-interface. This application also implemented important security measures to protect sensitive data as well as to prevent common and serious security vulnerabilities.
  
This application also comes with a database - **music_database.db**, which stores the data related in the application.

In addition, the application generates a log file – **access.log**, which records all activities conducted by all users.


## 2. Security Features

*   **AES-256 Encryption (using `cryptography` library):**

      All documents and audio files are encrypted using the Advanced Encryption Standard (AES) with a 256-bit key. This ensures that the data is protected from unauthorized access, even if the database is compromised. AES is a widely recognized and robust symmetric encryption algorithm, suitable for securing sensitive information [1]. The `cryptography` library is used because it provides a high-level, easy-to-use interface to AES and other cryptographic algorithms, while also being actively maintained and audited for security vulnerabilities [4].  The encryption key is derived from the password you enter when adding documents or audio files. If you forget the password, you will not be able to decrypt the data. *Justification:* AES encryption with a 256-bit key provides strong protection for data at rest. It is a widely accepted standard for securing sensitive data and is resistant to known cryptanalytic attacks given the key size.
   
*   **Password Hashing (using `bcrypt` library):**
  
      User passwords are not stored in plain text. Instead, they are hashed using bcrypt, a strong adaptive hashing algorithm. Bcrypt incorporates a salt to protect against rainbow table attacks and is computationally intensive, making it resistant to brute-force attacks [2]. *Justification:*  bcrypt is used because it is specifically designed for password hashing. Its adaptive nature allows the hashing time to be increased as computing power improves, maintaining its resistance to brute-force attacks over time.  It's a standard recommendation for secure password storage [5].
    
*   **Input Sanitization (using `re` module):**
  
      The application implements input sanitization techniques, using regular expressions from the `re` module, to prevent injection attacks such as SQL injection and cross-site scripting (XSS). User inputs, such as filenames and usernames, are validated and sanitized to remove or escape potentially harmful characters [3]. *Justification:* Input sanitization is crucial to prevent attackers from injecting malicious code into the application through user-supplied data. Regular expressions provide a powerful and flexible way to define patterns for valid input and to identify and remove potentially harmful characters.  Properly implemented input validation is a fundamental security practice [6].



## 3. Installation

### Prerequisites

*   Python 3.6 or higher

### Windows

1.  Open a command prompt (search for "cmd" in the Start menu).
2.  Navigate to the directory where you saved the `music_copyright-v15.py` script using the `cd` command.
3.  Run the following command to install the required Python packages:

    ```
    pip install cryptography bcrypt
    ```

### macOS

1.  Open a terminal (search for "Terminal" in Spotlight).
2.  Navigate to the directory where you saved the `music_copyright-v15.py` script using the `cd` command.
3.  Run the following command to install the required Python packages:

    ```
    pip3 install cryptography bcrypt
    ```


## 4. Usage

1.  **Save the Script:** Save the provided Python script (`music_copyright-v15.py`) to a directory on your computer.
2.  **Run the Script:**

    *   Open a command prompt (Windows) or terminal (macOS).
    *   Navigate to the directory where you saved the script using the `cd` command.
    *   Run the script using the following command:

        ```
        python music_copyright-v15.py
        ```

3.  **Follow the Prompts:** The script will guide you through a menu-driven interface to register users, log in, add documents/audio files, retrieve them, and perform other management tasks.

## 5. Functions Rundown
*Login page*
1.	**Register:** Register an account in order to login and conduct different action such as create & update artifacts.
2.	**Login:** Login as administrator or a registered account
3.	**Exit:** Exit the application

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

## Important Considerations

*   **Password Security:** Choose strong, unique passwords for your user accounts.

## Code Explanation

*   **`encrypt(data, password)`:** This function encrypts the given data using AES-256 with a key derived from the provided password. It uses a random initialization vector (IV) for added security.
*   **`decrypt(encrypted_data, password)`:** This function decrypts the encrypted data using the same AES-256 key derived from the password.
*   **`register_user()`:** This function registers a new user, hashing their password using bcrypt before storing it in the database.
*   **`login_user()`:** This function authenticates a user by comparing the entered password with the bcrypt hash stored in the database.
*   **`validate_filename(filename)` and `validate_username(username)`:** These functions use regular expressions to validate filenames and usernames, preventing invalid or potentially malicious inputs.
*   **`sanitize_filename(filename)`:** This function sanitizes filenames to remove potentially harmful characters.
*   **`log_activity(activity, username)`:** This function logs user activity to an "access.log" file for auditing purposes.

## Academic References

[1]  National Institute of Standards and Technology (NIST). (2001). *Advanced Encryption Standard (AES)*. FIPS PUB 197. [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

[2]  Provos, N., & Mazières, D. (1999). *A Future-Adaptable Password Scheme*. Proceedings of the 1999 USENIX Annual Technical Conference. [https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf](https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf)

[3]  OWASP Foundation. (2024). *Input Validation Cheat Sheet*. [https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

[4]  Cryptography Development Team. (2024). *cryptography*. [https://cryptography.io/en/latest/](https://cryptography.io/en/latest/)

[5]  Wheeler, D. A. (2023). *Secure Password Storage*. [https://dwheeler.com/essays/passwords.html](https://dwheeler.com/essays/passwords.html)

[6]  Seacord, R. C. (2013). *Secure Coding in C and C++*. Addison-Wesley Professional. (Relevant sections on input validation).

