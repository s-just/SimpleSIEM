import re
from siem_core import Syslog

class LogFilter:
    """ Parses and evaluates custom filter strings against Syslog objects. """

    # Map filter keys (lowercase) to Syslog object
    FIELD_MAP = {
        "pid": lambda log: str(log.pid or ""),
        "hostname": lambda log: str(log.hostname or "").lower(),
        "severity": lambda log: str(log.severity_info[0] or "").lower() if log.severity_info else "",
        "facility": lambda log: str(log.facility_info[0] or "").lower() if log.facility_info else "",
        "process": lambda log: str(log.process_name or "").lower(),
        "message": lambda log: str(log.message or "").lower(),
        "timestamp": lambda log: str(log.timestamp or ""),
        "priority": lambda log: str(log.priority or ""),
    }

    # Regex to parse a single condition : field=value, field="value", message("value")
    # Allows operators... Handles numbers and quoted strings... Handles message() function.
    CONDITION_REGEX = re.compile(
        r"\s*(\w+)\s*" # 1: Field name (..., PID, Hostname)
        r"(?:" # Start group
        r"([=!]=?)" # 2: Operator (=, ==, !=)
        r"\s*(\d+|'[^\']*'|\"[^\"]*\")" # 3: Value (number, single or double quoted string)
        r"|" # OR
        r"\(\s*(\d+|'[^\']*'|\"[^\"]*\")\s*\)" # 4: Value for function style like message("...")
        r")\s*" # End group
        , re.IGNORECASE
    )

    def __init__(self, filter_string=""):
        self.filter_string = filter_string.strip()
        self.parsed_filter = None
        self.error = None
        if self.filter_string:
            try:
                self.parsed_filter = self._parse()
            except ValueError as e:
                self.error = str(e)
                self.parsed_filter = None

    def _parse(self):
        """ Parses the filter string into a structure for evaluation.
            Structure: List of OR groups, where each group is a List of AND conditions.
            Example: 'PID=1 && Host="A" || Sev="err"' -> [[(pid,=,1), (host,=,A)], [(sev,=,err)]]
        """
        if not self.filter_string:
            return [] # Empty filter matches everything

        or_groups = []
        for or_part in self.filter_string.split('||'):
            and_conditions = []
            for and_part in or_part.split('&&'):
                and_part = and_part.strip()
                if not and_part:
                    continue # Skip empty parts

                match = self.CONDITION_REGEX.fullmatch(and_part)
                if not match:
                    raise ValueError(f"Invalid condition syntax: '{and_part}'")

                field = match.group(1).lower()
                operator = match.group(2) # =, ==, !=
                value = match.group(3)    # Number or quoted string for =/!=
                func_value = match.group(4) # Value for function style message("...")

                if field not in self.FIELD_MAP:
                    raise ValueError(f"Unknown filter field: '{field}'")

                if func_value is not None:
                    if field != "message": # Only allow message() syntax
                         raise ValueError(f"Function syntax (...) only valid for 'message', not '{field}'")
                    operator = "contains" # Internal operator name
                    value = func_value
                elif operator is None:
                    raise ValueError(f"Missing operator/value for field: '{field}'")

                if isinstance(value, str):
                    if value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    elif value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    if field not in ["pid", "priority"] or operator == "contains":
                         value = value.lower()

                condition = (field, operator, value)
                and_conditions.append(condition)

            if and_conditions:
                or_groups.append(and_conditions)

        if not or_groups and self.filter_string:
             raise ValueError("Filter string provided but no valid conditions found.")

        return or_groups

    def matches(self, syslog_obj: Syslog) -> bool:
        """ Checks if a Syslog object matches the parsed filter. """
        if self.error: # Don't match if filter is invalid
             return False
        if not self.parsed_filter:
            return True # Empty or cleared filter matches everything

        # Check OR groups
        for and_group in self.parsed_filter:
            all_and_conditions_met = True
            # Check AND conditions within the group
            for field, operator, filter_value in and_group:
                if field not in self.FIELD_MAP:
                     all_and_conditions_met = False
                     break

                # Get the actual value from the syslog object using the mapping
                try:
                    actual_value = self.FIELD_MAP[field](syslog_obj)
                except Exception:
                    actual_value = ""

                # Perform comparison
                match_found = False
                if operator == "contains":
                    match_found = filter_value in actual_value
                elif operator == "=" or operator == "==":
                    match_found = actual_value == str(filter_value)
                elif operator == "!=":
                    match_found = actual_value != str(filter_value)

                if not match_found:
                    all_and_conditions_met = False
                    break

            # If all AND conditions in this OR group were met, the whole filter matches
            if all_and_conditions_met:
                return True

        # If no OR group matched... filter fails
        return False