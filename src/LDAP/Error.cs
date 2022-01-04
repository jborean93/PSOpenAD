using System;

namespace PSOpenAD.LDAP
{
    public enum LDAPResultCode
    {
        Success = 0,
        OperationsError = 1,
        ProtocolError = 2,
        TimeLimitExceeded = 3,
        SizeLimitExceeded = 4,
        CompareFalse = 5,
        CompareTrue = 6,
        AuthMethodNotSupported = 7,
        StrongerAuthRequired = 8,
        PartialResults = 9,
        Referral = 10,
        AdminLimitExceeded = 11,
        UnavailableCriticalExtension = 12,
        ConfidentialityRequired = 13,
        SaslBindInProgress = 14,
        NoSuchAttribute = 15,
        UndefinedAttributeType = 16,
        InappropriateMatching = 18,
        ConstraintViolation = 19,
        AttributeOrValueExists = 20,
        InvalidAttributeSyntax = 21,
        NoSuchObject = 32,
        AliasProblem = 33,
        InvalidDNSyntax = 34,
        IsLeaf = 35,
        AliasDereferencingProblem = 36,
        XProxyAuthzFailure = 47,
        InappropriateAuthentication = 48,
        InvalidCredentials = 49,
        InsufficientAccessRights = 50,
        Busy = 51,
        Unavailable = 52,
        UnwillingToPerform = 53,
        LoopDetect = 54,
        NamingViolation = 64,
        ObjectClassViolation = 65,
        NotAllowedOnNonLeaf = 66,
        NotAllowedOnRDN = 67,
        EntryAlreadyExists = 68,
        ObjectClassModsProhibited = 69,
        ResultTooLarge = 70,
        AffectsMultipleDSAs = 71,
        VlvError = 76,
        Other = 80,
        CupResourcesExhausted = 113,
        CupSecurityViolation = 114,
        CupInvalidData = 115,
        CupUnsupportedScheme = 116,
        CupReloadRequired = 117,
        Cancelled = 118,
        NoSuchOperation = 119,
        TooLate = 120,
        CannotCancel = 121,
        AssertionFaled = 122,
        ProxiedAuthorizationDenied = 123,
        SyncRefreshRequired = 4096,
        XSyncRefreshRequired = 16640,
        XNoOperation = 16654,
        XAssertionFailed = 16655,
        TxnSpecifyOkay = 16672,
        TxnIdInvalid = 16673,
        ServerDown = -1,
        LocalError = -2,
        EncodingError = -3,
        DecodingError = -4,
        Timeout = -5,
        AuthUnknown = -6,
        FilterError = -7,
        UserCancelled = -8,
        ParamError = -9,
        NoMemory = -10,
        ConnectError = -11,
        NotSupported = -12,
        ControlNotFound = -13,
        NoResultsReturned = -14,
        MoreResultsToReturn = -15,
        ClientLoop = -16,
        ReferralLimitExceeded = -17,
        XConnecting = -18,
    }

    public class LDAPException : Exception
    {
        public string DiagnosticsMessage { get; internal set; } = "";
        public LDAPResultCode ResultCode { get; internal set; } = LDAPResultCode.Other;

        public LDAPException() { }

        public LDAPException(string message) : base(message) { }

        public LDAPException(string message, Exception innerException) :
            base(message, innerException)
        { }

        internal LDAPException(LDAPResult result) : base(BuildErrorMessage(result))
        {
            DiagnosticsMessage = result.DiagnosticsMessage;
            ResultCode = result.ResultCode;
        }

        private static string BuildErrorMessage(LDAPResult result)
        {
            string msg = CodeToString(result.ResultCode);
            if (!String.IsNullOrWhiteSpace(result.DiagnosticsMessage))
                msg += $" - {result.DiagnosticsMessage}";

            return msg;
        }

        private static string CodeToString(LDAPResultCode code) => code switch
        {
            LDAPResultCode.Success => "Success",
            LDAPResultCode.OperationsError => "Operations error",
            LDAPResultCode.ProtocolError => "Protocol error",
            LDAPResultCode.TimeLimitExceeded => "Time limit exceeded",
            LDAPResultCode.SizeLimitExceeded => "Size limit exceeded",
            LDAPResultCode.CompareFalse => "Compare False",
            LDAPResultCode.CompareTrue => "Compare True",
            LDAPResultCode.AuthMethodNotSupported => "Authentication method not supported",
            LDAPResultCode.StrongerAuthRequired => "Strong(er) authentication required",
            LDAPResultCode.PartialResults => "Partial results and referral received",
            LDAPResultCode.Referral => "Referral",
            LDAPResultCode.AdminLimitExceeded => "Administrative limit exceeded",
            LDAPResultCode.UnavailableCriticalExtension => "Critical extension is unavailable",
            LDAPResultCode.ConfidentialityRequired => "Confidentiality required",
            LDAPResultCode.SaslBindInProgress => "SASL bind in progress",
            LDAPResultCode.NoSuchAttribute => "No such attribute",
            LDAPResultCode.UndefinedAttributeType => "Undefined attribute type",
            LDAPResultCode.InappropriateMatching => "Inappropriate matching",
            LDAPResultCode.ConstraintViolation => "Constraint violation",
            LDAPResultCode.AttributeOrValueExists => "Type or value exists",
            LDAPResultCode.InvalidAttributeSyntax => "Invalid syntax",
            LDAPResultCode.NoSuchObject => "No such object",
            LDAPResultCode.AliasProblem => "Alias problem",
            LDAPResultCode.InvalidDNSyntax => "Invalid syntax",
            LDAPResultCode.IsLeaf => "Entry is a leaf",
            LDAPResultCode.AliasDereferencingProblem => "Alias dereferencing problem",
            LDAPResultCode.XProxyAuthzFailure => "Proxy Authorization Failure (X)",
            LDAPResultCode.InappropriateAuthentication => "Inappropriate authentication",
            LDAPResultCode.InvalidCredentials => "Invalid credentials",
            LDAPResultCode.InsufficientAccessRights => "Insufficient access",
            LDAPResultCode.Busy => "Server is busy",
            LDAPResultCode.Unavailable => "Server is unavailable",
            LDAPResultCode.UnwillingToPerform => "Server is unwilling to perform",
            LDAPResultCode.LoopDetect => "Loop detected",
            LDAPResultCode.NamingViolation => "Naming violation",
            LDAPResultCode.ObjectClassViolation => "Object class violation",
            LDAPResultCode.NotAllowedOnNonLeaf => "Operation not allowed on non-leaf",
            LDAPResultCode.NotAllowedOnRDN => "Operation not allowed on RDN",
            LDAPResultCode.EntryAlreadyExists => "Already exists",
            LDAPResultCode.ObjectClassModsProhibited => "Cannot modify object class",
            LDAPResultCode.ResultTooLarge => "Results too large",
            LDAPResultCode.AffectsMultipleDSAs => "Operation affects multiple DSAs",
            LDAPResultCode.VlvError => "Virtual List View error",
            LDAPResultCode.Other => "Other (e.g., implementation specific) error",
            LDAPResultCode.CupResourcesExhausted => "LCUP Resources Exhausted",
            LDAPResultCode.CupSecurityViolation => "LCUP Security Violation",
            LDAPResultCode.CupInvalidData => "LCUP Invalid Data",
            LDAPResultCode.CupUnsupportedScheme => "LCUP Unsupported Scheme",
            LDAPResultCode.CupReloadRequired => "LCUP Reload Required",
            LDAPResultCode.Cancelled => "Cancelled",
            LDAPResultCode.NoSuchOperation => "No Operation to Cancel",
            LDAPResultCode.TooLate => "Too Late to Cancel",
            LDAPResultCode.CannotCancel => "Cannot Cancel",
            LDAPResultCode.AssertionFaled => "Assertion Failed",
            LDAPResultCode.ProxiedAuthorizationDenied => "Proxied Authorization Denied",
            LDAPResultCode.SyncRefreshRequired => "Content Sync Refresh Required",
            LDAPResultCode.XSyncRefreshRequired => "Content Sync Refresh Required (X)",
            LDAPResultCode.XAssertionFailed => "Assertion Failed (X)",
            LDAPResultCode.XNoOperation => "No Operation (X)",
            LDAPResultCode.TxnSpecifyOkay => "TXN specify okay",
            LDAPResultCode.TxnIdInvalid => "TXN ID is invalid",
            LDAPResultCode.ServerDown => "Can't contact LDAP server",
            LDAPResultCode.LocalError => "Local error",
            LDAPResultCode.EncodingError => "Encoding error",
            LDAPResultCode.DecodingError => "Decoding error",
            LDAPResultCode.Timeout => "Timed out",
            LDAPResultCode.AuthUnknown => "Unknown authentication method",
            LDAPResultCode.FilterError => "Bad search filter",
            LDAPResultCode.UserCancelled => "User cancelled operation",
            LDAPResultCode.ParamError => "Bad parameter to an ldap routine",
            LDAPResultCode.NoMemory => "Out of memory",
            LDAPResultCode.ConnectError => "Connect error",
            LDAPResultCode.NotSupported => "Not Supported",
            LDAPResultCode.ControlNotFound => "No results returned",
            LDAPResultCode.NoResultsReturned => "More results to return",
            LDAPResultCode.MoreResultsToReturn => "Client Loop",
            LDAPResultCode.ClientLoop => "Client Loop",
            LDAPResultCode.ReferralLimitExceeded => "Referral Limit Exceeded",
            LDAPResultCode.XConnecting => "Connecting (X)",
            _ => "Unknown error",
        };
    }
}
