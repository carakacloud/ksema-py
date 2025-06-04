from dataclasses import dataclass
from typing import Optional, Dict

# Data classes for JSON serialization/deserialization

@dataclass
class Data:
    message: str
    retCode: int

@dataclass
class AuthRequest:
    apiKey: str
    pin: str

@dataclass
class AuthData:
    sessionId: str
    userType: int

@dataclass
class AuthResponse:
    success: bool
    data: AuthData
    error: Optional[str]

@dataclass
class ServiceRequest:
    sessionId: str
    operation: str
    label: Optional[str] = None
    data: Optional[bytes] = None

@dataclass
class ServiceResponse:
    success: bool
    data: Data
    error: Optional[str]

# Constants
DEFAULT_RANDOM_LEN = 32
USER_OBJECT = 2

FAILED = 0
SUCCESS = 1
NOLABELFOUND = 2
MAXUSAGE = 3
UNAUTHORIZEDFUNC = 4
INVALIDPACKET = 5
KEYEXISTED = 6
PININCORRECT = 7
PINLOCKED = 8
SESSIONINVALID = 9
INVALIDENCRYPTED = 10

FunctionPing = "PING"
FunctionEncrypt = "ENCRYPT"
FunctionDecrypt = "DECRYPT"
FunctionSign = "SIGN"
FunctionVerify = "VERIFY"
FunctionRNG = "RNG"
FunctionBackup = "BACKUP"
FunctionRestore = "RESTORE"
FunctionDelete = "DELETE"
FunctionGenKeySym = "GENKEYSYM"
FunctionGenKeyAsym = "GENKEYASYM"
FunctionSetIV = "SETIV"

mapRetCodeToString: Dict[int, str] = {
    FAILED: "Failure",
    SUCCESS: "Success",
    NOLABELFOUND: "No Label Found",
    MAXUSAGE: "Max Usage",
    UNAUTHORIZEDFUNC: "Unauthorized Function",
    INVALIDPACKET: "Invalid Packet",
    KEYEXISTED: "Key Already Existed",
    PININCORRECT: "PIN Incorrect",
    PINLOCKED: "PIN Locked",
    SESSIONINVALID: "Session Invalid",
    INVALIDENCRYPTED: "Invalid Encrypted Data",
}
