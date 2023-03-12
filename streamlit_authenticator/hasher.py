from typing import Union
import bcrypt

class Hasher:
    """
    This class will hash plain text passwords.
    """
    def __init__(self, passwords: list, salt: Union[None, bytes] = None):
        """
        Create a new instance of "Hasher".

        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        salt : NoneType or bytes, optional
            Customized value of the salt to be used during the hashing operation        
        """
        self.passwords = passwords
        if salt == None:
            self.bsalt = bcrypt.gensalt()
        else:
            self.bsalt = salt

    def _hash(self, password: str) -> str:
        """
        Hashes the plain text password.

        Parameters
        ----------
        password: str
            The plain text password to be hashed.
        Returns
        -------
        str
            The hashed password.
        """
        return bcrypt.hashpw(password.encode(), self.bsalt).decode()

    def generate(self) -> list:
        """
        Hashes the list of plain text passwords.

        Returns
        -------
        list
            The list of hashed passwords.
        """
        return [self._hash(password) for password in self.passwords]
