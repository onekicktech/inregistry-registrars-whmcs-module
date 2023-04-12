<?php

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

require_once __DIR__ . '/lib/Config.php';

function inregistry_MetaData()
{
    return ["DisplayName" => "IN Registry", "APIVersion" => "1.0.0", "NonLinearRegistrationPricing" => true];
}

function inregistry_GetConfigArray()
{
    return [
        "Description" => [
            "Type" => "System",
            "Value" => "3rd Party WHMCS Module for IN Registry: <a href=\"https://www.registry.in/about-registry\" target=\"_blank\">www.registry.in/registrar-registration</a>",
        ],

        'local_cert' => [
            'FriendlyName' => 'Signed Certificate',
            'Type' => 'text',
            'Default' => 'csr-signed.pem',
            'Description' => 'This CSR is signed by IN Registry. It must be a PEM encoded file.',
        ],
        'local_pk' => [
            'FriendlyName' => 'Private Key',
            'Type' => 'text',
            'Default' => 'username-key.pem',
            'Description' => 'Private Key.',
        ],
        'passphrase' => [
            'FriendlyName' => 'Pass Phrase',
            'Type' => 'password',
            'Size' => '32',
            'Description' => 'Enter pass phrase with which your certificate file was encoded.',
        ],
        'clid' => [
            'FriendlyName' => 'Client ID',
            'Type' => 'text',
            'Size' => '20',
            'Description' => 'Client identifier.',
        ],
        'pw' => [
            'FriendlyName' => 'Password',
            'Type' => 'password',
            'Size' => '20',
            'Description' => "Client's plain text password.",
        ],

        'identityprefix' => [
            'FriendlyName' => 'Identity Prefix',
            'Type' => 'text',
            'Size' => '4',
            'Description' => 'Registry assigns each registrar a unique prefix with which that registrar must create contact IDs.',
        ],

        "TestMode" => [
            "Type" => "yesno",
        ],
    ];
}

function inregistry_config_validate($params)
{
    if (!$params["clid"]) {
        throw new WHMCS\Exception\Module\InvalidConfiguration("Missing IN Registry EPP Username. Please navigate to Configuration (<i class=\"fa fa-wrench\" aria-hidden=\"true\"></i>) > System Settings > Domain Registrars to configure.");
    }

    if (!$params["pw"]) {
        throw new WHMCS\Exception\Module\InvalidConfiguration("Missing IN Registry EPP Password. Please navigate to Configuration (<i class=\"fa fa-wrench\" aria-hidden=\"true\"></i>) > System Settings > Domain Registrars to configure.");
    }

    if (!$params["local_cert"] || !file_exists($params["local_cert"])) {
        throw new WHMCS\Exception\Module\InvalidConfiguration("Missing IN Registry Signed Certificate. Please navigate to Configuration (<i class=\"fa fa-wrench\" aria-hidden=\"true\"></i>) > System Settings > Domain Registrars to configure.");
    }

    if (!$params["local_pk"] || !file_exists($params["local_pk"])) {
        throw new WHMCS\Exception\Module\InvalidConfiguration("Missing IN Registry Private Key. Please navigate to Configuration (<i class=\"fa fa-wrench\" aria-hidden=\"true\"></i>) > System Settings > Domain Registrars to configure.");
    }

    if (strlen($params['identityprefix']) > 4) {
        throw new WHMCS\Exception\Module\InvalidConfiguration("Identity Prefix max length limit is 4 character");
    }

    $con = ok_epp_startEppClient($params);
    if (!empty($con->error)) {
        throw new WHMCS\Exception\Module\InvalidConfiguration($con->error);
    }
}

function inregistry_GetNameservers(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    $nss = ok_epp_GetNameservers($params, $domainName);

    $return = [];
    if (isset($nss['error'])) {
        $return = $nss;
    } else {
        if (!empty($nss) && is_array($nss)) {
            $i = 0;
            foreach ($nss as $ns) {
                $i++;
                $return["ns{$i}"] = $ns;
            }
        }
    }

    return $return;
}

function inregistry_SaveNameservers(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    $nss = [];
    foreach (['ns1', 'ns2', 'ns3', 'ns4', 'ns5'] as $nsv) {
        if (!empty($params[$nsv])) {
            $nss[] = $params[$nsv];
        }
    }
    return ok_epp_SaveNameservers($params, $domainName, $nss);
}

function inregistry_GetDomainExtensionGroup()
{
    return ok_epp_gTld();
}

function inregistry_getDomainName(WHMCS\Domains\Domain $domain, $skipFilter = false)
{
    $domainName = $domain->getDomain();
    if ($skipFilter) {
        return $domainName;
    }
    if (function_exists("mb_strtolower")) {
        return mb_strtolower($domainName);
    }
    if (preg_replace("/[^a-z0-9-.]/i", "", $domainName) === $domainName) {
        return strtolower($domainName);
    }
    return $domainName;
}

function inregistry_GetRegistrarLock(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_GetRegistrarLock($params, $domainName);
}

function inregistry_SaveRegistrarLock(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $lockenabled = isset($params["lockenabled"]) && $params["lockenabled"] === "locked" ? "locked" : "unlocked";
    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_SaveRegistrarLock($params, $domainName, $lockenabled);
}

function inregistry_RegisterDomain(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $nss = [];
    foreach (['ns1', 'ns2', 'ns3', 'ns4', 'ns5'] as $nsv) {
        if (!empty($params[$nsv])) {
            $nss[] = $params[$nsv];
        }
    }
    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_RegisterDomain($params, $domainName, $nss);
}

function inregistry_TransferDomain(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    if (empty($params['transfersecret'])) {
        return ["error" => "Empty Trasfer Secret Code"];
    }
    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_TransferDomain($params, $domainName, $params['transfersecret']);
}

function inregistry_RenewDomain(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_RenewDomain($params, $domainName);
}

function inregistry_GetContactDetails(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_GetContactDetails($params, $domainName);
}

function inregistry_SaveContactDetails(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_SaveContactDetails($params, $domainName);
}

function inregistry_GetEPPCode(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_GetEPPCode($params, $domainName);
}

function inregistry_RegisterNameserver(array $params)
{
    return ok_epp_RegisterNameserver($params);
}

function inregistry_ModifyNameserver(array $params)
{
    return ok_epp_ModifyNameserver($params);
}

function inregistry_DeleteNameserver(array $params)
{
    return ok_epp_DeleteNameserver($params);
}

function inregistry_RequestDelete(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_RequestDelete($params, $domainName);
}

function inregistry_Sync(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_SyncDomain($params, $domainName);
}

function inregistry_TransferSync(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_epp_TransferDomainSync($params, $domainName);
}

// _GetTldPricing

// inregistry_GetDNS
// inregistry_SaveDNS
// inregistry_GetEmailForwarding
// inregistry_SaveEmailForwarding

// inregistry_ReleaseDomain
// inregistry_DomainSync

// _GetDomainSuggestions
// GetPremiumPrice
// GetDomainInformation
// ResendIRTPVerificationEmail
// inregistry_CheckAvailability

function inregistry_AdminCustomButtonArray()
{
    $buttonarray = [];
    $domainId = $_REQUEST['domainid'] ?? $_REQUEST["id"];
    $params = get_query_vals("tbldomains", "", ["id" => $domainId ?? null]);
    if (is_array($params) && $params["type"] == "Transfer" && $params["status"] === "Pending Transfer") {
        $buttonarray["Cancel Domain Transfer"] = "canceldomaintransfer";
    }
    $buttonarray["Change EPP Code"] = "changeEppCode";

    return $buttonarray;
}

function inregistry_changeEppCode(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    return ok_ep_AuthinfoUpdate($params, $domainName);
}

function inregistry_canceldomaintransfer(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    $ck = ok_epp_cancelDomainTransfer($params, $domainName);
    if (!isset($ck['error']) && !empty($params["domainid"])) {
        update_query("tbldomains", ["status" => "Cancelled"], ["id" => $params["domainid"]]);
    }
    return $ck;
}

// Disclose element not supported on .IN Registrar
function inregistry_IDProtectToggle(array $params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    if (empty($params["domainid"])) {
        return ["error" => "Empty Domain Id"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    $idprotect = ($params['protectenable'] ? 1 : 0);

    $domUp = ok_epp_IDProtectToggle($params, $domainName, $idprotect);
    if (isset($domUp['success'])) {
        update_query("tbldomains", ["idprotection" => $idprotect], ["id" => $params["domainid"]]);
    }
    return $domUp;
}

// Called when a domain is viewed within WHMCS. Recommended instead of GetNameservers and GetRegistrarLock in WHMCS 7.6 and later.
function inregistry_GetDomainInformation($params)
{
    $params = injectDomainObjectIfNecessary($params);
    if (empty($params['domainObj']) && empty($params['domainname'])) {
        return ["error" => "Empty Domain Name"];
    }

    $domainName = !empty($params['domainObj']) ? inregistry_getDomainName($params['domainObj']) : inregistry_getDomainName($params['domainname']);
    $response = ok_epp_GetDomainInformation($params, $domainName);

    $nameservers = [];
    $i = 0;
    foreach ($response["ns"] as $ns) {
        $i++;
        $nameservers["ns{$i}"] = $ns;
    }

    if (empty($response['authInfo'])) {
        $currentstatus = "deleted";
    } elseif (in_array("inactive", $response["status"]) || in_array("pendingtransfer", $response["status"])) {
        $currentstatus = "inactive";
    } elseif (in_array("pendingDelete", $response["status"])) {
        $currentstatus = "pendingDelete";
    } else {
        $currentstatus = "active";
    }

    $hasidprotect = ($params['idprotection'] ?? false);
    $hasdnsmanagement = ($params['dnsmanagement'] ?? false);
    $hasemailforwarding = ($params['emailforwarding'] ?? false);

    $isIcannTld = false; //country-code so false ?? if generic then true

    $transferLock = in_array('clientTransferProhibited', $response['status']) ? true : false;

    $irtpOptOut = true;
    $triggerFields = [];
    if (!array_key_exists("DesignatedAgent", $params) || !$params["DesignatedAgent"]) {
        $triggerFields = ["Registrant" => ["Full Name", "Company Name", "Email"]];
        $irtpOptOut = false;
    }

    $expirydate = WHMCS\Carbon::createFromFormat('Y-m-d', date("Y-m-d", $response['exDate']));
    $irtpLock = strtotime($response['crDate']) < (time() - (60 * 24 * 60 * 60)); //sixtydaylock

    return (new WHMCS\Domain\Registrar\Domain())
        ->setDomain($response['name'])
        ->setNameservers($nameservers)
        ->setRegistrationStatus(inregistry_normalise_status($currentstatus))
        ->setTransferLock($transferLock)
        ->setTransferLockExpiryDate(null)
        ->setExpiryDate($expirydate) // $response['exDate'] = YYYY-MM-DD
        ->setRestorable(false)
        ->setIdProtectionStatus($hasidprotect)
        ->setDnsManagementStatus($hasdnsmanagement)
        ->setEmailForwardingStatus($hasemailforwarding)
        ->setIsIrtpEnabled($isIcannTld)
        ->setIrtpOptOutStatus($irtpOptOut)
        ->setIrtpTransferLock($irtpLock)

        ->setDomainContactChangePending(null) //raaVerificationStatus ==== Pending then true
        ->setPendingSuspension(false) // raaVerificationStartTime
        ->setDomainContactChangeExpiryDate(null) //

        ->setRegistrantEmailAddress($response['registrant']['email'])
        ->setIrtpVerificationTriggerFields($triggerFields);
}

function inregistry_normalise_status($status)
{
    switch ($status) {
        case "inactive":
            return WHMCS\Domain\Registrar\Domain::STATUS_INACTIVE;
            break;
        case "suspended":
            return WHMCS\Domain\Registrar\Domain::STATUS_SUSPENDED;
            break;
        case "pendingDelete":
            return WHMCS\Domain\Registrar\Domain::STATUS_PENDING_DELETE;
            break;
        case "deleted":
            return WHMCS\Domain\Registrar\Domain::STATUS_DELETED;
            break;
        default:
            return WHMCS\Domain\Status::ACTIVE;
    }
}
