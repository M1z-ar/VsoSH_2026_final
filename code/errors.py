class ScanError(Exception):
    pass


class RateError(ScanError):
    pass


class TempError(ScanError):
    pass


class FatalError(ScanError):
    pass


class InputError(ScanError):
    pass
