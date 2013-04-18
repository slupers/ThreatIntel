class DataProvider(object):
    class Result(object):
        POSITIVE = 1
        INDETERMINATE = 2
        NEGATIVE = 3

        def __init__(self, disposition, info):
            self.disposition = disposition
            self.info = info
