# palo-alto-config
This script will push some configuration base on the JSON including in this repository.

1. Push an Antivirus Profile
2. Push an AntiSpyware Profile
3. Push a URL-Profile
4. Deploy a Vulnerability Profile
5. Set up a Zone Protection Profile
6. Push a Wildfile Profile
7. And, craft some Security Policy rules that fend off pesky malicious IPs!
8. *More to be added

The profiles created is based on palo alto internet gateway best practice security policy.
https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles

- I do not have this on my dynamic list yet, maybe because of I am running this on VM. but I added this on external dynamic list
![image](https://github.com/romarroca/palo-alto-config/assets/87074019/972a11f9-38d6-4ea2-9926-bc6c9415c913)

## The script will add the following External Dynamic IP lists and block traffic to/from it.
- https://lists.blocklist.de/lists/all.txt
- https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt

## change this to your environment
![image](https://github.com/romarroca/palo-alto-config/assets/87074019/6e48c684-89dd-4348-8a33-f428e3a117df)
 
## Disclaimer
Just a quick heads-up if you're thinking of using this script:

- You Do You: Basically, you're running this on your own dime. If anything goes sideways, it's on you. Just so we're clear.
- Not Magic, Just a Tool: This script is like a cool sidekick, not the superhero. If you know your stuff about configurations, it's here to make your life a bit easier. But don't expect it to do all the heavy lifting or make decisions for you.
- Know What's Up: Please, oh please, get what this script is all about before hitting "Run." It'll save both of us a headache.

Use wisely! 

## TO DO
- Add external dynamic domain lists
- Test on Panorama
- !

Tested Palo-Alto versions
- PAN OS 11.0.0 KVM
- Currently supports rest-api restapi v10.2

## Video Demo
- https://www.youtube.com/watch?v=L9tcSOAkHJY

