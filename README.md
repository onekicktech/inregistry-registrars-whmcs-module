# .IN Registry WHMCS Module Installation instructions

This is Unofficially .in domain name registry WHMCS module
(EPP: RFC 5730, 5731, 5732, 5733, 5734, 5910)

1. Download and install [WHMCS](https://whmcs.com/)

2. Place the repository as **inregistry** directory in `[WHMCS]/modules/registrars`

3. place your **username-key.pem (Private Key)** and **csr-signed.pem (CSR is signed by IN Registry)** files in secure path.

4. Configure from Configuration -> System Settings -> Domain Registrars

5. Add a new TLD using Configuration -> System Settings -> Domain Pricing

---

## Registry Connection Details

- **EPP Server (TCP 700):** epp.nixiregistry.in  
- **Registrar Console:** https://console.nixiregistry.in  
- **WHOIS (TCP 43):** whois.nixiregistry.in/  
- **WHOIS Web:** https://whois.nixiregistry.in/  
- **RDAP:** rdap.nixiregistry.in/  
- **OT&E EPP Server (TCP 700):** epp.ote.nixiregistry.in  
- **OT&E Registrar Console:** https://console.ote.nixiregistry.in  
- **OT&E WHOIS:** https://whois.ote.nixiregistry.in/  

**Status:** https://www.tucowsregistrystatus.com/

If you are unable to locate these credentials or are having trouble accessing the OT&E, please reply to this email or reach out to [transitionsupport@nixi.in](mailto:transitionsupport@nixi.in).

You should be good to go