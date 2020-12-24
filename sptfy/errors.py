

class SptfyError(Exception):
    pass


class SptfyOAuthError(SptfyError):
    def __init__(self, message, error=None, error_description=None):
        self.message = message
        self.error = error
        self.error_description = error_description
        super().__init__(self.message)


class SptfyOAuthRedirect(SptfyError):
    def __init__(self, message, redirect_url=None):
        self.redirect_url = redirect_url
        super().__init__(message)


class SptfyRequestError(SptfyError):
    pass
