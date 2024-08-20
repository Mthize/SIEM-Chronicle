# SIEM - Chronicle

**SIEM** (Security Information and Event Management) is an application that collects, aggregates, and analyzes log data to monitor critical activities within an organization.

**Chronicle** is a cloud-based SIEM platform built on Google’s core infrastructure. It allows enterprises to securely retain, analyze, and search massive amounts of security and network telemetry.

## Overview

In Chronicle, security analysts can search for events using the search field. Procedural Filtering allows users to apply filters to refine search results further, such as including or excluding specific event types or log sources. Additionally, Chronicle supports YARA-L, a specialized language used to create rules for searching through ingested log data.

There are two primary search modes in Chronicle:

- **Unified Data Model (UDM) Search**: The default search mode in Chronicle, UDM Search queries data that has been ingested, parsed, and normalized, making searches faster due to the indexed and structured data.
- **Raw Log Search**: This mode searches through unparsed, raw logs. While more flexible in terms of data points you can query (e.g., usernames, filenames, hashes), it is slower than UDM Search. Regular expressions can also be used to match specific patterns.

## Scenario

You are a security analyst at a financial services company. An alert is raised indicating that an employee received a phishing email. Upon reviewing the alert, you identify a suspicious domain in the email body: `signin.office365x24.com`. Your task is to investigate whether other employees received similar emails, whether anyone visited the domain, and determine any further threats. You will use [Chronicle](https://demo.backstory.chronicle.security/?warstory=) to investigate this domain.

## Expectations

- Access threat intelligence reports on the domain.
- Identify which assets accessed the domain.
- Evaluate the HTTP events associated with the domain.
- Determine which assets submitted login information to the domain.
- Identify any additional related domains.

## Step-by-Step

### 1. Launch Chronicle

- Access your Chronicle account.

### 2. Perform a Domain Search

- In the search bar, type `signin.office365x24.com` and click **Search**. Under `DOMAINS`, select `signin.office365x24.com` to view the results. The following are key points from the legacy view, VirusTotal (VT) integration, and the IP address `40.100.174.34`:

  - **Image 1: Legacy View**

    ![chrome_QnyIg5thvH](https://github.com/user-attachments/assets/05fefaac-289b-43fc-8129-6b80f1b03e75)

  - **Image 2: VT View**

    ![chrome_u1p0eD2S4u](https://github.com/user-attachments/assets/6582e189-68b0-4ed5-a3e7-93059a2ad9fa)

  - **Image 3: IP Address `40.100.174.34`**

    ![chrome_WS7N0VCXT1](https://github.com/user-attachments/assets/aa812c10-364b-4e68-a447-8e1d1582c6ba)

### 3. Evaluate the Search Results (Legacy View)

| **Observe**             | **Description**                                                                                          | **Note**                                                                                                                      |
|:-----------------------:|----------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------|
| **VT Context**          | Provides VirusTotal information about the domain.                                                        | Chronicle identified that 7 security vendors flagged this domain as malicious.                                                |
| **WHOIS**               | Summarizes information about the domain, including owner contact details and registration data.          | Useful for determining the origin of malicious websites. The domain was first seen 7 months ago, as of February 10th, 2024.   |
| **Prevalence**          | Displays the historical access pattern of the domain.                                                    | The domain was accessed on July 9th, 2023, and February 10th, 2024.                                                           |
| **Resolved IP**         | Provides IP addresses associated with the domain.                                                        | Two IP addresses map to `signin.office365x24.com`: `104.215.148.63` & `40.100.174.34`.                                        |
| **Sibling Domains**     | Displays related domains under the same parent domain.                                                   | One sibling domain found: `login.office365x24.com`.                                                                           |
| **ET Intelligence Rep List** | Includes threat intelligence details from ProofPoint's Emerging Threats (ET) Intelligence Rep List. | Category: Drop site for logs or stolen credentials. Confidence: 22/127, Severity: Medium, Active from: 2018-12-31 T00:00:00Z, Active until: 2019-01-08 T00:00:00Z. More info can be found [here](https://tools.emergingthreats.net/docs/ET%20Intelligence%20Rep%20List%20Tech%20Description.pdf). |
| **Timeline**            | Details the events and interactions with the domain.                                                     | Reveals HTTP requests, including `GET` and `POST` methods.                                                                    |
| **ASSETS**              | Lists assets that accessed the domain.                                                                   | 6 assets accessed the domain.                                                                                                 |

### 4. Launch an Investigation

- According to the ET Intelligence Rep List, `signin.office365x24.com` is categorized as a "Drop site for logs or stolen credentials."
- The following assets accessed the domain:
    - `ashton-davidson-pc`
    - `bruce-monroe-pc`
    - `coral-alvarez-pc`
    - `emil-palmer-pc`
    - `jude-reyes-pc`
    - `roger-spence-pc`
- The IP address `40.100.174.34` is linked to both `signin.office365x24.com` and `signin.accounts-google.com`.
- Several `POST` requests were made to `signin.office365x24.com`, targeting URLs like `http://signin.office365x24.com/login.php`.
