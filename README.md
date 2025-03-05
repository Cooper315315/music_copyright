# Music Copyright Management System

## 1. Introduction

This Python application provides a secure system for managing music-related documents and audio files. It allows users to store, retrieve, and manage their music-related assets in a protected environment. The system incorporates strong security measures to protect sensitive data, including AES-256 encryption for data storage, bcrypt for password hashing, and input sanitization to prevent common security vulnerabilities.

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

## Important Considerations

*   **Password Security:** Choose strong, unique passwords for your user accounts.
*   **Data Backup:** Regularly back up the `music_database.db` file to prevent data loss.
*   **Key Management:** The encryption key is derived from the password you enter when adding documents or audio files. If you forget the password, you will not be able to decrypt the data. Consider using a password manager to store your passwords securely.

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

## Disclaimer

This application is provided as-is, with no warranty of any kind. The user assumes all responsibility for the security of their data. While the security measures implemented in this application are intended to provide a high level of protection, no system can be completely secure.
![image](https://github.com/user-attachments/assets/e08ac863-e99c-4651-95c2-81746d1633c9)
