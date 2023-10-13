from .Cvss import Cvss


class Cve:
    def __init__(self):
        self.raw: str = None
        self.cve_id: str = None
        self.cwe_id: str = None
        self.description: str = None
        self.source: str = None
        self.references: list = None

        self.cvss_v2: Cvss = None
        self.cvss_v3: Cvss = None

        self.published_date: str = None
        self.updated_date: str = None

    def __repr__(self):
        # Return a string representation that can recreate the object
        return (str(vars(self)))
