# Cybersecurity Incident Response Showcase

This repository documents my work on various cybersecurity incident response scenarios, including vulnerability analysis, incident handling, and password cracking.

## Contents

* **CISA Advisory Response:** Responding to the CISA Log4j advisory.
# CISA Advisory Response

This folder contains my response to the CISA Log4j advisory.

## Files

* `Log4j_Advisory_Email.txt`: The advisory email sent to affected teams.

## Description

This email demonstrates my ability to communicate critical vulnerability information to affected teams, providing context and remediation steps.

Subject: URGENT: Critical Log4j Vulnerability (CVE-2021-44228) - Immediate Action Required

Dear [Team Lead Name] and Team,

This is an urgent notification regarding a critical zero-day vulnerability (CVE-2021-44228) in Apache Log4j, a widely used logging library. The Cybersecurity and Infrastructure Security Agency (CISA) has issued an advisory highlighting the severity of this vulnerability, which allows for remote code execution.

**Impact:**

This vulnerability poses a significant risk to our systems, as it could allow attackers to gain unauthorized access and control. Given the potential for widespread exploitation, immediate action is crucial.

**Affected Systems (Based on Infrastructure List):**

* **Product Development Staging Environment (Product Development Team, John Doe):** This environment is confirmed to be running Log4j.

**Required Actions:**

1.  **Immediate Patching/Mitigation:**
    * The Product Development team must immediately update Log4j to the latest patched version (2.17.0 or later).
    * If patching is not immediately feasible, implement the mitigation measures recommended by Apache and CISA, which involve setting the `log4j2.formatMsgNoLookups` system property to `true` or removing the `JndiLookup` class from the classpath.
2.  **Vulnerability Scanning:**
    * Conduct thorough vulnerability scans of all systems within your team's responsibility to identify any other potential instances of Log4j.
3.  **Incident Response Planning:**
    * Review and update your incident response plans to address potential exploitation of this vulnerability.
4.  **Continuous Monitoring:**
    * Implement continuous monitoring of system logs for any suspicious activity related to Log4j.
5.  **Communication:**
    * Please reply to this email to confirm that you have received this notification and are taking the necessary steps to mitigate the vulnerability. Please provide a timeline for your mitigation efforts.
6.  **Coordination:**
    * Please coordinate with the central security team to ensure that all response actions are aligned.

**Resources:**

* CISA Log4j Advisory: [Link to CISA Log4j Advisory]
* Apache Log4j Security Vulnerabilities: [Link to Apache Log4j Security Page]

**Importance of Timely Action:**

The Log4j vulnerability is being actively exploited in the wild. Prompt action is essential to protect our systems from potential attacks.

If you have any questions or require assistance, please contact the Cybersecurity Incident Response Team immediately at [Incident Response Team Contact Information].

Thank you for your immediate attention to this critical matter.

Sincerely,

AIG Cybersecurity Team



# Log4j Incident

This folder documents the handling of a simulated Log4j exploitation and ransomware incident.

## Files

* `Incident_Report.md`: A report detailing the incident, response actions, and lessons learned.

Log4j Ransomware Incident Report

## Incident Summary

* **Vulnerability:** CVE-2021-44228 (Log4j)
* **Attack Vector:** Remote code execution via Log4j vulnerability.
* **Impact:** Partial ransomware encryption of one zip file.
* **Response:** Incident Detection & Response team contained the attack, preventing full encryption.

## Response Actions

1.  **Vulnerability Patching:** Immediate patching of Log4j.
2.  **Incident Containment:** Network isolation of the affected server.
3.  **Ransomware Analysis:** Analysis of the ransomware payload.
4.  **Decryption Attempt:** Brute-force decryption of the encrypted zip file.
5.  **Incident Reporting:** Reporting to relevant stakeholders.

## Lessons Learned

* Importance of timely patching.
* Need for robust incident response plans.
* Value of brute-forcing techniques in specific scenarios.

## Description

This report outlines the steps taken to contain and recover from a simulated ransomware attack resulting from a Log4j vulnerability exploitation. It highlights incident response skills and decision-making in a high-pressure scenario.

# Brute-Force Script

This folder contains a Python script to brute-force zip file passwords.

## Files

* `bruteforce_zip.py`: The Python script.
* `rockyou_subset.txt`: A subset of the Rockyou password list.
* `encrypted_file.zip` (Optional): An encrypted zip file for testing.

## Description

The `bruteforce_zip.py` script demonstrates a practical approach to password cracking using a wordlist. It iterates through the password list, attempting to decrypt the zip file until the correct password is found.

import zipfile

def bruteforce_zip(zip_file_path, password_list_path):
    """
    Brute-forces a zip file password using a provided password list.

    Args:
        zip_file_path (str): The path to the encrypted zip file.
        password_list_path (str): The path to the password list file.

    Returns:
        str: The decrypted password if found, otherwise None.
    """
    try:
        with open(password_list_path, 'r', encoding='latin-1') as password_file:
            for password in password_file:
                password = password.strip()  # Remove newline characters
                try:
                    with zipfile.ZipFile(zip_file_path) as zf:
                        zf.extractall(pwd=password.encode('utf-8'))
                    return password  # Password found!
                except RuntimeError:
                    # Incorrect password, try the next one
                    pass
                except zipfile.BadZipFile:
                    return "Bad Zip File"
        return None  # Password not found
    except FileNotFoundError:
        return "File Not Found"

# Example usage (replace with your file paths)
zip_file_path = "encrypted_file.zip"  # Replace with the actual zip file path
password_list_path = "rockyou_subset.txt"  # Replace with your password list path

decrypted_password = bruteforce_zip(zip_file_path, password_list_path)

if decrypted_password:
    print(f"Password found: {decrypted_password}")
else:
    print("Password not found in the provided list.")

## Key Demonstrations

* **Vulnerability Analysis:** Analyzing and responding to critical vulnerabilities (Log4j).
* **Incident Handling:** Handling a ransomware incident, including containment and recovery.
* **Password Cracking:** Developing a Python script for brute-forcing zip file passwords.
* **Communication:** Crafting clear and effective advisory emails.

This repository demonstrates practical skills in incident response and security analysis.
