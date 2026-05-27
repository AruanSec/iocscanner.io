# config.py
from dataclasses import dataclass
from dotenv import load_dotenv
import os

load_dotenv()

@dataclass(frozen=True)
class Config:
    virustotal_api_key: str
    abuseipdb_api_key: str
    shodan_api_key: str
    anyrun_api_key: str
    hybridanalysis_api_key: str
    phishtank_api_key: str
    database_url: str
    shodan_monthly_quota: int = 100

    def __post_init__(self):
        missing = [f for f in self.__dataclass_fields__ 
                   if not getattr(self, f) and f != "shodan_monthly_quota"]
        if missing:
            raise EnvironmentError(f"Missing required env vars: {missing}")

cfg = Config(
    virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
    abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
    shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
    anyrun_api_key=os.getenv("ANYRUN_API_KEY", ""),
    hybridanalysis_api_key=os.getenv("HYBRIDANALYSIS_API_KEY", ""),
    phishtank_api_key=os.getenv("PHISHTANK_API_KEY", ""),
    database_url=os.getenv("DATABASE_URL", ""),
)
