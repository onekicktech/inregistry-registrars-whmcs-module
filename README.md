# .IN Registry WHMCS Module Installation instructions

This is Unofficially .in domain name registry WHMCS module
EPP: RFC 5730, 5731, 5732, 5733, 5734, 5910

1. Download and install [WHMCS](https://whmcs.com/)

2. Place the repository as **inregistry** directory in `[WHMCS]/modules/registrars`

3. place your **username-key.pem (Private Key)** and **csr-signed.pem (CSR is signed by IN Registry)** files in secure path.

4. Configure from Configuration -> System Settings -> Domain Registrars

5. Add a new TLD using Configuration -> System Settings -> Domain Pricing


You should be good to go now.