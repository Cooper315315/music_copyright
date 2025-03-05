# Music Copyright Management System

## 1. Introduction

*   This Python application provides a secure system for managing music-related documents and audio files. It allows users to store, retrieve, and manage their music-related assets in a protected environment. The system incorporates strong security measures to protect sensitive data, including AES-256 encryption for data storage, bcrypt for password hashing, and input sanitization to prevent common security vulnerabilities.

## 2. Security Features

*   **AES-256 Encryption:** All documents and audio files are encrypted using the Advanced Encryption Standard (AES) with a 256-bit key. This ensures that the data is protected from unauthorized access, even if the database is compromised. AES is a widely recognized and robust encryption algorithm, suitable for securing sensitive information [1].  The encryption key is derived from the password you enter when adding documents or audio files. If you forget the password, you will not be able to decrypt the data.
*   **bcrypt Password Hashing:** User passwords are not stored in plain text. Instead, they are hashed using bcrypt, a strong adaptive hashing algorithm. Bcrypt incorporates a salt to protect against rainbow table attacks and is computationally intensive, making it resistant to brute-force attacks [2].
*   **Input Sanitization:** The application implements input sanitization techniques to prevent injection attacks such as SQL injection and cross-site scripting (XSS). User inputs, such as filenames and usernames, are validated and sanitized to remove or escape potentially harmful characters [3].

## 3. Installation

### Prerequisites

*   Python 3.6 or higher
*   `pip` (Python package installer)

### Windows

1.  **Install Python:**

    *   Download the latest version of Python from the official website: [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
    *   Run the installer and ensure that you select the option to add Python to your PATH environment variable.
2.  **Install Dependencies:**

    *   Open a command prompt (search for "cmd" in the Start menu).
    *   Navigate to the directory where you saved the `music_copyright-v15.py` script using the `cd` command.
    *   Run the following command to install the required Python packages:

        ```
        pip install cryptography bcrypt
        ```

### macOS

1.  **Install Python:**

    *   macOS usually comes with Python pre-installed, but it's often an older version. It's recommended to install a newer version using Homebrew.
    *   If you don't have Homebrew, install it from the official website: [https://brew.sh/](https://brew.sh/)
    *   Open a terminal (search for "Terminal" in Spotlight).
    *   Run the following command to install Python 3:

        ```
        brew install python3
        ```
2.  **Install Dependencies:**

    *   Open a terminal.
    *   Navigate to the directory where you saved the `music_copyright-v15.py` script using the `cd` command.
    *   Run the following command to install the required Python packages:

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

