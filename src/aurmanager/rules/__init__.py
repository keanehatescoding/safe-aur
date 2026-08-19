from .exfiltration import (
    EXF001SshKeyExfiltration,
    EXF002GnupgExfiltration,
    EXF003BrowserCredentialExfiltration,
    EXF004EnvironmentExfiltration,
    EXF005DeveloperCloudCredentialExfiltration,
)
from .integrity import (
    INT001PkgverNetworkCall,
    INT002SuspiciousSourceHost,
    INT003SkippedChecksumOnNetworkSource,
    INT005InstallHookPullsUnpinnedDeps,
    INT006SrcinfoPkgbuildMismatch,
)
from .meta import META001UnparseableInput
from .obfuscation import (
    OBF001Base64DecodeExec,
    OBF002EvalUsage,
    OBF003HexEscapePayload,
    OBF004Rot13DecodeExec,
)
from .patch import PAT001PipedExecAddedByPatch
from .persistence import (
    PER001ShellRcWrite,
    PER002CronPersistence,
    PER003SystemdEnableAtBuildTime,
    PER004AutostartWrite,
    PER005AuthorizedKeysAppend,
    PER006DisguisedBinaryDrop,
)
from .privesc import PRV001SudoInBuildLifecycle, PRV002SudoersEdit, PRV003SetuidBit
from .rce import (
    RCE001CurlPipeBash,
    RCE002ProcessSubstitutionSource,
    RCE003FetchThenExecute,
    RCE004DisguisedSourceExecuted,
)

ALL_RULES = [
    RCE001CurlPipeBash,
    RCE002ProcessSubstitutionSource,
    RCE003FetchThenExecute,
    RCE004DisguisedSourceExecuted,
    OBF001Base64DecodeExec,
    OBF002EvalUsage,
    OBF003HexEscapePayload,
    OBF004Rot13DecodeExec,
    PER001ShellRcWrite,
    PER002CronPersistence,
    PER003SystemdEnableAtBuildTime,
    PER004AutostartWrite,
    PER005AuthorizedKeysAppend,
    PER006DisguisedBinaryDrop,
    PRV001SudoInBuildLifecycle,
    PRV002SudoersEdit,
    PRV003SetuidBit,
    EXF001SshKeyExfiltration,
    EXF002GnupgExfiltration,
    EXF003BrowserCredentialExfiltration,
    EXF004EnvironmentExfiltration,
    EXF005DeveloperCloudCredentialExfiltration,
    INT001PkgverNetworkCall,
    INT002SuspiciousSourceHost,
    INT003SkippedChecksumOnNetworkSource,
    INT005InstallHookPullsUnpinnedDeps,
    INT006SrcinfoPkgbuildMismatch,
    META001UnparseableInput,
    PAT001PipedExecAddedByPatch,
]
