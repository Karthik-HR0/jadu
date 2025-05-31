
<div align="center">

<h3>
  <b>
    
![IMG_20250331_114354](https://github.com/user-attachments/assets/8a186c35-455f-4bdc-89d9-b1c557d3ebb6)

    
  <kbd><a href="https://github.com/Karthik-HR0/jadu">JADU</a></kbd>
    
  <kbd>the full version release soon with new feature!!! </kbd>
  </b>
</h3>

</div>

<div align="center">
  
  <a href="#features">`Features`</a> •
  <a href="#installation">`Installation`</a> •
  <a href="#usage">`Usage`</a> •
  <a href="#patterns">`Patterns`</a> •
  
  <a href="#sample-output">`Sample Output`</a>

</div> 

<p align="center">
  <img src="https://img.shields.io/badge/go-1.16+-blue.svg" alt="Go 1.16+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <a href="https://twitter.com/Karthik__hr"><img src="https://img.shields.io/twitter/follow/KarthikHR0.svg?logo=X"></a>
</p>

<h6 align="center">
  <b>Jadu</b> - A fast, multithreaded command-line tool to detect secrets and sensitive keys in web content. Perfect for security researchers, developers, and pentesters.
</h6>

<br>
<br>

<h1 align="center">
  
  Features

</h1>

<div align="center">
  
| Category             | Core Capabilities                     | Advanced Functionality              | Customization & Output          |
|----------------------|---------------------------------------|-------------------------------------|-------------------------------|
| **Scanning**         | • _`Regex-based Secret Detection`_   | • _`Sensitive Key Identification`_ | • _`Custom Pattern Support`_ |
|                      | • _`Multithreaded Processing`_       | • _`Version Checking`_             | • _`Detailed Line Numbers`_  |
| **HTTP Handling**    | • _`Custom User-Agent`_              | • _`Cookie Support`_               | • _`SSL Skip Verification`_  |
|                      | • _`GET Request Automation`_         | • _`Error Recovery`_               |                              |
| **Output Control**   | • _`Color-coded Results`_            | • _`Silent Mode`_                  | • _`Pattern Display`_        |
|                      | • _`URL-based Reporting`_            | • _`Duplicate Suppression`_        |                              |

</div>

<br>
<br>

## Installation

Install directly from source:

```bash
go install github.com/Karthik-HR0/jadu@latest
```

Or build manually:
```bash
git clone https://github.com/Karthik-HR0/jadu.git
cd jadu
go build -o jadu main.go
```

<br>
<br>

## Usage

### Basic Scanning
```bash
echo "https://example.com/script.js" | jadu
```

### Advanced Examples
1. Detailed scan with custom settings:
```bash
cat urls.txt | jadu -d -ua "Mozilla/5.0" -t 100
```

2. Scan with custom pattern:
```bash
echo "https://example.com" | jadu -ep "secret-[a-z0-9]{10}"
```

3. Save results and filter:
```bash
cat urls.txt | jadu -d | tee results.txt
```

4. Check for updates:
```bash
jadu -up
```

5. Show all patterns:
```bash
jadu -show-patterns
```

<h3>Arguments</h3>

<table>
  <thead>
    <tr>
      <th>Argument</th>
      <th>Description</th>
      <th>Default</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>-s</code></td>
      <td>Silent mode (no banner)</td>
      <td><code>false</code></td>
    </tr>
    <tr>
      <td><code>-t</code></td>
      <td>Number of threads</td>
      <td><code>50</code></td>
    </tr>
    <tr>
      <td><code>-ua</code></td>
      <td>Custom User-Agent</td>
      <td><code>"Jadu"</code></td>
    </tr>
    <tr>
      <td><code>-c</code></td>
      <td>Custom cookies</td>
      <td><code>""</code></td>
    </tr>
    <tr>
      <td><code>-d</code></td>
      <td>Detailed output (line numbers)</td>
      <td><code>false</code></td>
    </tr>
    <tr>
      <td><code>-ep</code></td>
      <td>Custom regex pattern</td>
      <td><code>""</code></td>
    </tr>
    <tr>
      <td><code>-sen</code></td>
      <td>Show only sensitive keys</td>
      <td><code>false</code></td>
    </tr>
    <tr>
      <td><code>-show-patterns</code></td>
      <td>Display patterns and exit</td>
      <td><code>false</code></td>
    </tr>
    <tr>
      <td><code>-up</code></td>
      <td>Check for updates</td>
      <td><code>false</code></td>
    </tr>
  </tbody>
</table>

<br>
<br>

## Patterns

Jadu scans for two types of secrets:

⇛ Regular Secrets
<details>
<summary>Examples</summary>

```plaintext
- Basic Auth Credential: Basic [A-Za-z0-9+/]{15}
- Slack Token: xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}
```
</details>

⇛ Sensitive Secrets
<details>
<summary>Examples</summary>

```plaintext
- Google API Key: AIza[0-9A-Za-z-_]{35}
- AWS Access Key ID: AKIA[0-9A-Z]{16}
- AWS Secret Access Key: [A-Za-z0-9/+=]{40}
- GitHub Personal Access Token: ghp_[0-9A-Za-z]{36}
```
</details>



<br>
<br>



<br>
<br>

## Sample Output

Here are examples of `Jadu`’s output with various flags. Colors are described since Markdown doesn’t render them.

<details>
<summary>Basic Scan</summary>

Command:
```bash
echo "https://example.com/script.js" | jadu
```

Output:
```
[+] https://example.com/script.js [Slack Token] [xoxb-123456789012-123456789012-123456789012-abcdef1234567890abcdef1234567890] (Green)
[+] https://example.com/script.js [Google API Key] [AIzaSyD_1234567890abcdef1234567890abc] (Red)
```

- Green: Regular secrets.
- Red: Sensitive secrets.
</details>

<details>
<summary>Detailed Output with Line Numbers</summary>

Command:
```bash
echo "https://example.com/script.js" | jadu -d
```

Output:
```
[*] Processing URL: https://example.com/script.js (Yellow)
[+] https://example.com/script.js [Basic Auth Credential] [Basic YWRtaW46cGFzc3dvcmQ=] [Line: 15] (Green)
[+] https://example.com/script.js [AWS Access Key ID] [AKIA1234567890ABCDEF] [Line: 42] (Red)
```

- Yellow: Info message.
- Green/Red: Secrets with line numbers.
</details>

<details>
<summary>Custom Pattern Scan</summary>

Command:
```bash
echo "https://example.com" | jadu -ep "secret-[a-z0-9]{10}"
```

Output:
```
[+] https://example.com [Custom Pattern] [secret-abc123xyz9] (Green)
```

- Custom matches shown as regular secrets.
</details>

<details>
<summary>Sensitive Keys Only</summary>

Command:
```bash
cat urls.txt | jadu -sen
```

Input (`urls.txt`):
```
https://example.com/script.js
https://test.com/config.js
```

Output:
```
[+] https://example.com/script.js [AWS Secret Access Key] [abcd1234/567890efghijklmn+opqrstuvwx==] (Red)
[+] https://test.com/config.js [GitHub Personal Access Token] [ghp_1234567890abcdef1234567890abcdefghijkl] (Red)
```

- Only sensitive secrets displayed.
</details>

<details>
<summary>Show Patterns</summary>

Command:
```bash
jadu -show-patterns
```

Output:
```
Regular Secret Patterns:
╒==============================╤=====================================================================================================╕
│ Name                         │ Pattern                                                                                            │
╞==============================╪=====================================================================================================╡
│ Basic Auth Credential        │ Basic [A-Za-z0-9+/]{15}                                                                           │
├──────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Slack Token                  │ (xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})                                        │
╘==============================╧=====================================================================================================╛

Sensitive Secret Patterns:
╒==============================╤=====================================================================================================╕
│ Name                         │ Pattern                                                                                            │
╞==============================╪=====================================================================================================╡
│ Google API Key               │ AIza[0-9A-Za-z-_]{35}                                                                             │
├──────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ AWS Access Key ID            │ AKIA[0-9A-Z]{16}                                                                                  │
├──────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ AWS Secret Access Key        │ [A-Za-z0-9/+=]{40}                                                                                │
├──────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ GitHub Personal Access Token │ ghp_[0-9A-Za-z]{36}                                                                               │
╘==============================╧=====================================================================================================╛
```

- Full pattern list in tables.
</details>

<details>
<summary>Update Check</summary>

Command:
```bash
jadu -up
```

Output (if up-to-date):
```
[+] Version 1.0 is the latest version (Green)
```

Output (if outdated):
```
[-] Version 1.0 is outdated. Latest version is 1.1 (Red)
```

Output (if check fails):
```
[-] Could not check version: unknown (error checking version) (Yellow)
```

- Version status feedback.
</details>






<details>
<summary>Add custom pattern</summary>




#### Custom Patterns
To permanently add secret or sensitive patterns, modify the secretsPatterns or sensitivePatterns arrays in the source code (main.go) and rebuild the tool.

Steps:
1. Edit the Source Code:
   - Open main.go in a text editor.
   - Locate the secretsPatterns (for regular secrets) or sensitivePatterns (for sensitive secrets) array.
   - Add your pattern using the SecretPattern struct: {Pattern: regexp.MustCompile("<regex-pattern>"), Label: "<label>"}.

2. Syntax for Adding a Pattern:
      {Pattern: regexp.MustCompile("<regex-pattern>"), Label: "<label>"},
   
   - <regex-pattern>: A valid Go regex string (e.g., mysecret-[a-zA-Z0-9]{8}).
   - <label>: A descriptive name (e.g., "My Secret Key").

3. Examples:
   - Add to Regular Secrets:
   - ```
          var secretsPatterns = []SecretPattern{
         // Existing patterns...
         {Pattern: regexp.MustCompile(`mysecret-[a-zA-Z0-9]{8}`), Label: "My Secret Key"},
     }
     ```
     
     - Output will appear in green.

   - Add to Sensitive Secrets:
   - ```
          var sensitivePatterns = []SecretPattern{
         // Existing patterns...
         {Pattern: regexp.MustCompile(`mysensitive-[0-9]{12}`), Label: "My Sensitive Token"},
     }

     ```
     - Output will appear in red.

4. Rebuild the Tool:
5. ```
      go build -o jadu main.go
   

</details>

```


     ____.           .___     
    |    |____     __| _/_ __ 
    |    \__  \   / __ |  |  \
/\__|    |/ __ \_/ /_/ |  |  /
\________(____  /\____ |____/ 
              \/      \/      

                                   [Coded by Karthik-HR0]
                                    [Version 1.0 (Latest)]

  -c string
        cookies
  -d    detailed
  -ep string
        extra, custom (regexp) pattern
  -s    silent
  -sen
        show only sensitive API keys
  -show-patterns
        display all available secret patterns and exit
  -t int
        thread number (default 50)
  -ua string
        User-Agent (default "Jadu")
  -up
        check for updates
                               

```

---

<p align="center">
Built with ❤️ by <a href="https://github.com/Karthik-HR0">@Karthik-HR0</a>
</p>
