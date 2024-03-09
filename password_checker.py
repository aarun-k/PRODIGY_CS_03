import re

class PasswordStrengthAssessor:
    """
    A class for assessing the strength of a password.
    """

    def __init__(self, password):
        """
        Initialize the PasswordStrengthAssessor object with the given password.

        :param password: The password to assess.
        """
        self.password = password

    def _has_minimum_length(self):
        """
        Check if the password has a minimum length of 8 characters.

        :return: True if the password has a minimum length of 8 characters, False otherwise.
        """
        return len(self.password) >= 8

    def _has_uppercase_letter(self):
        """
        Check if the password has at least one uppercase letter.

        :return: True if the password has at least one uppercase letter, False otherwise.
        """
        return any(char.isupper() for char in self.password)

    def _has_lowercase_letter(self):
        """
        Check if the password has at least one lowercase letter.

        :return: True if the password has at least one lowercase letter, False otherwise.
        """
        return any(char.islower() for char in self.password)

    def _has_digit(self):
        """
        Check if the password has at least one digit.

        :return: True if the password has at least one digit, False otherwise.
        """
        return any(char.isdigit() for char in self.password)

    def _has_special_char(self):
        """
        Check if the password has at least one special character.

        :return: True if the password has at least one special character, False otherwise.
        """
        special_chars = r'[!@#$%^&*()_+{}\[\]:;<>,.?/~`]'
        return bool(re.search(special_chars, self.password))

    def assess_strength(self):
        """
        Assess the strength of the password based on various criteria.

        :return: A string indicating the password's strength.
        """
        criteria_checks = [
            self._has_minimum_length(),
            self._has_uppercase_letter(),
            self._has_lowercase_letter(),
            self._has_digit(),
            self._has_special_char()
        ]

        score = sum(criteria_checks)
        password_length = len(self.password)

        if password_length < 8:
            return "Very weak"
        elif password_length < 12:
            return "Weak" if score >= 2 else "Very weak"
        elif password_length < 16:
            return "Moderate" if score >= 3 else "Weak"
        elif password_length < 20:
            return "Strong" if score >= 4 else "Moderate"
        else:
            return "Extremely strong" if score == 5 else "Strong"

if __name__ == "__main__":
    password = input("Enter your password: ") # Type your password in the place of password if call callback error occurs
    assessor = PasswordStrengthAssessor(password)
    strength = assessor.assess_strength()
    print("Password strength:", strength)
