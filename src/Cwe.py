class Cwe:
    def __init__(self):
        self.cwe_id: str = None
        self.name: str = None
        self.description: str = None

    def __repr__(self):
        # Return a string representation that can recreate the object
        return(str(vars(self)))