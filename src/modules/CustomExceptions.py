class PasswordLengthException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class PasswordIllegalCharException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class PasswordLackingCharsException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class PasswordCommonException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class UsernameTakenException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class UserNotFounException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class InvalidFilenameException(Exception):
    def __init__(self, *args):
        super().__init__(*args)