def convert_facility(fac_val):
    match fac_val:
        case 0:
            return ("kern", "kernel messages")
        case 1:
            return ("user", "user-level messages")
        case 2:
            return ("mail", "mail system")
        case 3:
            return ("daemon", "system daemons")
        case 4:
            return ("auth", "security/authorization messages")
        case 5:
            return ("syslog", "messages generated internally by syslogd")
        case 6:
            return ("lpr", "line printer subsystem")
        case 7:
            return ("news", "network news subsystem")
        case 8:
            return ("uucp", "UUCP subsystem")
        case 9:
            return ("cron", "clock daemon")
        case 10:
            return ("authpriv", "security/authorization messages (private)")
        case 11:
            return ("ftp", "FTP daemon")
        case 12:
            return ("ntp", "NTP subsystem")
        case 13:
            return ("security", "log audit")
        case 14:
            return ("console", "log alert")
        case 15:
            return ("solaris-cron", "scheduling daemon")
        case 16:
            return ("local0", "local use 0")
        case 17:
            return ("local1", "local use 1")
        case 18:
            return ("local2", "local use 2")
        case 19:
            return ("local3", "local use 3")
        case 20:
            return ("local4", "local use 4")
        case 21:
            return ("local5", "local use 5")
        case 22:
            return ("local6", "local use 6")
        case 23:
            return ("local7", "local use 7")
        case _:
            return ("unknown", f"unknown facility value:{fac_val}")

def convert_severity(sev_val):
    match sev_val:
        case 0:
            return ("emergency", "system is unusable")
        case 1:
            return ("alert", "action must be taken immediately")
        case 2:
            return ("critical", "critical conditions")
        case 3:
            return ("error", "error conditions")
        case 4:
            return ("warning", "warning conditions")
        case 5:
            return ("notice", "normal but significant condition")
        case 6:
            return ("informational", "informational messages")
        case 7:
            return ("debug", "debug-level messages")
        case _:
            return ("unknown", f"unknown severity value:{sev_val}")

def categorize_priority_value(priority_value):
    facility_value = priority_value // 8
    severity_value = priority_value % 8

    severity_name, _ = convert_severity(severity_value)
    facility_name, _ = convert_facility(facility_value)

    if severity_name in ["emergency", "alert", "critical"]:
        return 0
    elif severity_name == "error":
        return 1
    elif severity_name in ["warning", "notice"]:
        return 2
    else:
        return 3