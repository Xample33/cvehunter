class Cvss:
    def __init__(self):
        self.score: float = None
        self.vector: str = None
        self.severity: str = None
        self.version: float = None
        self.exploitability: float = None
        self.impact: float = None

    def __eq__(self, other):
        if isinstance(other, dict):
            return vars(self) == other
        elif isinstance(other, Cvss):
            return vars(self) == vars(other)
        return False

    def __repr__(self) -> str:
        # Return a string representation that can recreate the object
        return(str(vars(self)))
