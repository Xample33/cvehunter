class Cvss:
    def __init__(self):
        self.score: float = None
        self.vector: str = None
        self.severity: str = None
        self.version: float = None
        self.exploitability: float = None
        self.impact: float = None

    def __repr__(self) -> str:
        # Return a string representation that can recreate the object
        return(str(vars(self)))