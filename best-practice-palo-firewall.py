import json
import requests

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def calculate_thresholds(A_CPS, P_CPS, AS, P_AS, EC):
    ALPHA, BETA, GAMMA, DELTA, ZETA = 0.2, 0.1, 0.8, 1.5, 2
    return (round(A_CPS + ALPHA * A_CPS), round(P_CPS + BETA * P_CPS), round(GAMMA * 268000),
            round(DELTA * AS), round(ZETA * EC),
            round(0.7 * round(A_CPS + ALPHA * A_CPS)), round(0.7 * round(P_CPS + BETA * P_CPS)), round(0.7 * round(GAMMA * 268000)),
            round(0.5 * round(A_CPS + ALPHA * A_CPS)), round(0.5 * round(P_CPS + BETA * P_CPS)), round(0.5 * round(GAMMA * 268000)))

def create_json_profile(AR, ActR, MR, Concurrent_Session_Limit, ET, AR_UDP, ActR_UDP, MR_UDP, AR_ICMP, ActR_ICMP, MR_ICMP):
    return {
        "entry": {
            "@name": "Custom_ZoneProtection_Profile",
            "description": "Custom Zone Protection Profile created programmatically.",
            "flood": {
                "tcp-syn": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": str(AR),
                        "activate-rate": str(ActR),
                        "maximal-rate": str(MR)
                    }
                },
                "udp": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": str(AR_UDP),
                        "activate-rate": str(ActR_UDP),
                        "maximal-rate": str(MR_UDP)
                    }
                },
                "icmp": {
                    "enable": "yes",
                    "red": {
                        "alarm-rate": str(AR_ICMP),
                        "activate-rate": str(ActR_ICMP),
                        "maximal-rate": str(MR_ICMP)
                    }
                }
            },
            "scan": {
                "entry": [
                    {
                        "@name": "8003",  # TCP Port Scan
                        "action": {
                            "block-ip": {
                                "track-by": "source",
                                "duration": "300"
                            }
                        },
                        "interval": "2",
                        "threshold": "100"
                    },
                    {
                        "@name": "8002",  # Host Sweep
                        "action": {
                            "block-ip": {
                                "track-by": "source",
                                "duration": "300"
                            }
                        },
                        "interval": "10",
                        "threshold": "100"
                    },
                    {
                        "@name": "8001",  # UDP Port Scan
                        "action": {
                            "block-ip": {
                                "track-by": "source",
                                "duration": "300"
                            }
                        },
                        "interval": "2",
                        "threshold": "100"
                    }
                ]
            },
            # Additional fields can be added here based on your requirements. For brevity, I only included a subset of the template.
            "discard-ip-spoof": "no",
            "discard-ip-frag": "yes",
            "strict-ip-check": "no",
            "discard-malformed-option": "yes"
        }
    }

def create_security_policy_rule_from_file(filename, name, location, vsys, restapi_version):
    data = load_json_from_file(filename)
    data['entry']['@name'] = name
    return data

def load_json_from_file(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)


def get_api_key(ip, username, password):
    url = f'https://{ip}/api/?type=keygen&user={username}&password={password}'
    response = requests.get(url, verify=False)
    return response.text.split('<key>')[1].split('</key>')[0]

def push_json_to_palo_alto(ip, username, password, json_data, restapi_version):
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Network/ZoneProtectionNetworkProfiles'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }

    params = {'name': 'Custom_ZoneProtection_Profile'}
    
    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_security_policy_to_palo_alto(ip, username, password, json_data, location, vsys, restapi_version):
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Policies/SecurityRules'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }

    params = {'name': json_data['entry']['@name'], 'location': location, 'vsys': vsys}
    
    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_vulnerability_profile_to_palo_alto(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/vulnerability_profile.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/VulnerabilityProtectionSecurityProfiles'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'best-practice-vuln', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_url_profile_to_palo_alto(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/best-practice-url.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/URLFilteringSecurityProfiles'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'best-practice-url', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_av_profile_to_palo_alto(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/best-practice-av.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/AntivirusSecurityProfiles'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'Strict_AV', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_spyware_profile_to_palo_alto(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/best-practice-spyware.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/AntiSpywareSecurityProfiles'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'best-practice-spyware', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_wildfire_profile_to_palo_alto(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/best-practice-wildfire.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/WildFireAnalysisSecurityProfiles'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'best-practice-wildfire', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_external_dynamic_ip1(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/external_dynamic_ip1.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/ExternalDynamicLists'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'lists.blocklist.de', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()

def push_external_dynamic_ip2(ip, username, password, location, vsys, restapi_version):
    json_data = load_json_from_file('config/external_dynamic_ip2.json')
    
    api_key = get_api_key(ip, username, password)
    url = f'https://{ip}/restapi/{restapi_version}/Objects/ExternalDynamicLists'
    
    headers = {
        "Content-Type": "application/json",
        "X-PAN-KEY": api_key
    }
    
    params = {'name': 'Emerging_Threats', 'location': location, 'vsys': vsys}

    response = requests.post(url, headers=headers, params=params, json=json_data, verify=False)
    return response.json()


def main():

    pa_ip, pa_username, pa_password = "192.168.8.200", "admin", "P@ssw0rd"

    print("""
    
    WELCOME TO THE PALO-ALTO CONFIG PUSHER
    
    Here's what we're gonna do:
    1 Push an Antivirus Profile
    2 Push an AntiSpyware Profile
    3 Push a URL-Profile
    4 Deploy a Vulnerability Profile
    5 Set up a Zone Protection Profile
    6 And, craft some Security Policy rules that fend off pesky malicious IPs!
    7 *To be added
    
    \U0001F6AB Just a quick heads-up if you're thinking of using this script

    - You Do You: Basically, you're running this on your own dime. If anything goes sideways, it's on you. Just so we're clear.
    - Not Magic, Just a Tool: This script is like a cool sidekick, not the superhero. If you know your stuff about configurations, 
      it's here to make your life a bit easier. But don't expect it to do all the heavy lifting or make decisions for you.
    - Know What's Up: Please, oh please, get what this script is all about before hitting "Run." It'll save both of us a headache.

    Use wisely! \U0001F6AB
    
    """)

    choice = input("Want to proceed? (yes/no): ").strip().lower()

    if choice != "yes":
        print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║ Thanks for stopping by! Remember, safety first. See you next time! ║
    ╚════════════════════════════════════════════════════════════════════╝
        """)
        exit()

    location_input = input("Enter location (default is 'vsys'): ")
    if not location_input:
        location_input = 'vsys'

    vsys_input = input("Enter vsys (default is 'vsys1'): ")
    if not vsys_input:
        vsys_input = 'vsys1'

    restapi_version_input = input("Enter restapi version (default is 'v10.2'): ")
    if not restapi_version_input:
        restapi_version_input = 'v10.2'
   
    print("""
    Please provide the following details as we will need it to craft our zone protection profile.
    If you are not sure of the value, you can put just an estimation.
    These numbers will be used to calculate AlarmRate, ActivationRate and MaximalRate for our ZoneProtection Profile.
    The Zone protection will not be in used and will be defined in the firewall, you will have the time to review it before
    applying it to an actual zone.
    """)

    A_CPS, P_CPS, AS, P_AS, EC = float(input("Average Connections per Second (A_CPS): ")), float(input("Peak Connections per Second (P_CPS): ")), float(input("Active Sessions (AS): ")), float(input("Peak Active Sessions (P_AS): ")), float(input("Embryonic Connections (EC): "))
    json_data = create_json_profile(*calculate_thresholds(A_CPS, P_CPS, AS, P_AS, EC))
    
    print("\nGenerated JSON Profile:\n", json.dumps(json_data, indent=4))

    save_to_file = input("\nDo you want to save this profile to a JSON file? (yes/no): ").lower()
    if save_to_file == 'yes':
        with open('config/zone_protection_profile.json', 'w') as json_file:
            json.dump(json_data, json_file, indent=4)
        print("JSON profile saved to 'zone_protection_profile.json'.")

    push_to_pa = input("\nDo you want to push this profile to Palo Alto? (yes/no): ").lower()
    if push_to_pa == 'yes':
        response = push_json_to_palo_alto(pa_ip, pa_username, pa_password, json_data, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto:\n", response)
    else:
        print("Exiting without pushing to Palo Alto.")

    
    
    print("""
   
    ╔════════════════════════════════════════════════════════════════════╗
    ║ Please review the content of vulnerability_profile.json            ║
    ╚════════════════════════════════════════════════════════════════════╝

    """)

    push_vuln_profile = input("\nDo you want to push the vulnerability profile to Palo Alto? (yes/no): ").lower()
    if push_vuln_profile == 'yes':
        response = push_vulnerability_profile_to_palo_alto(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto for Vulnerability Profile:\n", response)
    else:
        print("Exiting without pushing vulnerability profile to Palo Alto.")

    print("""

    ╔════════════════════════════════════════════════════════════════════╗
    ║ Please review the content of best-practice-url.json                ║
    ╚════════════════════════════════════════════════════════════════════╝

    """)

    push_url_profile = input("\nDo you want to push the URL profile to Palo Alto? (yes/no): ").lower()
    if push_url_profile == 'yes':
        response = push_url_profile_to_palo_alto(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto for URL Profile:\n", response)
    else:
        print("Exiting without pushing URL profile to Palo Alto.")

    print("""

    ╔════════════════════════════════════════════════════════════════════╗
    ║ Please review the content of best-practice-av.json                 ║
    ╚════════════════════════════════════════════════════════════════════╝

    """)

    push_av_profile = input("\nDo you want to push the anti-virus profile to Palo Alto? (yes/no): ").lower()
    if push_url_profile == 'yes':
        response = push_av_profile_to_palo_alto(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto for anti-virus profile:\n", response)
    else:
        print("Exiting without pushing anti-virus profile to Palo Alto.")

    print("""

    ╔════════════════════════════════════════════════════════════════════╗
    ║ Please review the content of best-practice-spyware.json            ║
    ╚════════════════════════════════════════════════════════════════════╝

    """)

    push_av_profile = input("\nDo you want to push the anti-spyware profile to Palo Alto? (yes/no): ").lower()
    if push_url_profile == 'yes':
        response = push_spyware_profile_to_palo_alto(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto for anti-spyware profile:\n", response)
    else:
        print("Exiting without pushing anti-spyware profile to Palo Alto.")


    print("""

    ╔════════════════════════════════════════════════════════════════════╗
    ║ Please review the content of best-practice-wildfire.json           ║
    ╚════════════════════════════════════════════════════════════════════╝

    """)

    push_av_profile = input("\nDo you want to push the wildfire profile to Palo Alto? (yes/no): ").lower()
    if push_url_profile == 'yes':
        response = push_wildfire_profile_to_palo_alto(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto for wildfire profile:\n", response)
    else:
        print("Exiting without pushing wildfire profile to Palo Alto.")

   

    print("""

    ╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║ Please review the content of security_policy_rule1.json and security_policy_rule2.json                      ║
    ╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

    """)

    push_security_rule = input("\nDo you want to push a security rule that blocks traffic to and from known bad IP to Palo Alto Firewall? (yes/no): ").lower()
    if push_security_rule == 'yes':
        print("\nDid you review the external dynamic lists for known bad IP? because I am adding it now.\n")
        response = push_external_dynamic_ip1(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        response = push_external_dynamic_ip2(pa_ip, pa_username, pa_password, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto for pushing external dynamic IP:\n", response)
        rule_name = input("\nEnter a name for the security rule (this will block traffic if the destination is going to BAD guys!): ")
        rule_data1 = load_json_from_file('config/security_policy_rule1.json')  
        rule_data1['entry']['@name'] = rule_name
        response = push_security_policy_to_palo_alto(pa_ip, pa_username, pa_password, rule_data1, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto:\n", response)

        rule_name = input("\nEnter a name for the security rule (this will block traffic if the source came from BAD guys!): ")
        rule_data2 = load_json_from_file('config/security_policy_rule2.json')  
        rule_data2['entry']['@name'] = rule_name
        response = push_security_policy_to_palo_alto(pa_ip, pa_username, pa_password, rule_data2, location=location_input, vsys=vsys_input, restapi_version=restapi_version_input)
        print("\nResponse from Palo Alto:\n", response)

    else:
        print("Exiting without pushing security rule to Palo Alto.")

    print("""

    Please check the added external dynamic lists from the following sources if you want to block
    this list of IP address:
    1. "https://lists.blocklist.de/lists/all.txt"
    2. "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"


    Make sure to check everything manually before committing!

    If you have and existing rule, the one we added here might be at the bottom and 
    make sure to drag it all the way up since we want blocking to bad source/destinations to be
    process first.

    Thank you!
    

    """)

if __name__ == "__main__":
    main()
