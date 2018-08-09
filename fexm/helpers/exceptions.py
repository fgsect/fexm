class CouldNotConfigureException(BaseException):
    def __str__(self):
        return "Could not configure the repository."


class NotABinaryExecutableException(BaseException):
    def __str__(self):
        return "The file given is not a binary executable"


class ParametersNotAcceptedException(BaseException):
    def __str__(self):
        return "The search parameters given were not accepted by the github api"


class NoCoverageInformation(BaseException):
    def __init__(self, binary_path):
        self.binary_path = binary_path

    def __str__(self):
        return "Could not get any coverage information for " + str(self.binary_path)
