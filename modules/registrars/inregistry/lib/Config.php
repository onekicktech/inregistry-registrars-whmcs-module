<?php

if (!defined("OKEPP_DEBUG_MODE")) {
    define("OKEPP_DEBUG_MODE", false); // if true -> Development Mode and Error log showing on display and write on Error Path
}

if (!defined("LOGS_DIR")) {
    define("LOGS_DIR", __DIR__ . "/../logs"); // Log path
}

if (function_exists("logModuleCall") && !defined("OKEPP_MODULE")) {
    define("OKEPP_MODULE", "inregistry"); //Module Names
}

ini_set("error_log", LOGS_DIR . '/epp_error.log');
ini_set('error_reporting', E_ALL);
ini_set('display_errors', OKEPP_DEBUG_MODE); //

require_once __DIR__ . '/Helper.php';
require_once __DIR__ . '/EppClient.php';

function ok_epp_buildConfig(array $config)
{
    return [
        "host" => !empty($config["TestMode"]) ? "epp.ote.nixiregistry.in" : "epp.nixiregistry.in",
        "port" => 700, // System port number 700 has been assigned by the IANA for mapping EPP onto TCP
        'local_cert' => $config['local_cert'],
        'local_pk' => $config['local_pk'],
        'passphrase' => $config['passphrase'],
        "identityprefix" => $config['identityprefix'], //use as indentifer alls request and max length is 4
        "tls_version" => "1.2", // Use more secure TLS 1.3 if the registry supports it.
    ];
}

function ok_epp_gTld()
{
    //ccTLD
    $in_supported_tld_list = '
.in
.us.in
.up.in
.uk.in
.tv.in
.travel.in
.dr.in
.delhi.in
.cs.in
.coop.in
.com.in
.cn.in
.ca.in
.business.in
.biz.in
.bihar.in
.am.in
.pro.in
.ai.in
.post.in
.6g.in
.pg.in
.5g.in
.me.in
.ind.in
.io.in
.firm.in
.internet.in
.gen.in
.int.in
.org.in
.info.in
.net.in
.gujarat.in
.co.in
.er.in
';
    return ["ccTLD" => ok_epp_line2arr($in_supported_tld_list)];
}

function ok_epp_domainStatus($isStatus = null)
{
    $domainStatus = [
        'clientDeleteProhibited',
        'clientHold',
        'clientRenewProhibited',
        'clientTransferProhibited',
        'clientUpdateProhibited',
        'inactive',
        'ok',
        'pendingCreate',
        'pendingDelete',
        'pendingRenew',
        'pendingTransfer',
        'pendingUpdate',
        'serverDeleteProhibited',
        'serverHold',
        'serverRenewProhibited',
        'serverTransferProhibited',
        'serverUpdateProhibited'
    ];

    return $isStatus === null ? $domainStatus : in_array($isStatus, $domainStatus);
}

function ok_epp_contactsType($isType = null)
{
    $contactsType = [
        'registrant',
        'tech',
        'admin',
        'billing'
    ];

    return $isType === null ? $contactsType : in_array($isType, $contactsType);
}

function ok_epp_trstatus($isStatus = null)
{
    $trstatus = [
        'clientApproved',
        'clientCancelled',
        'clientRejected',
        'pending',
        'serverApproved',
        'serverCancelled'
    ];
    return $isStatus === null ? $trstatus : in_array($isStatus, $trstatus);
}

//for WHMCS Module
function ok_epp_modulelog($send, $responsedata, $action)
{
    $from = $to = [];
    $from[] = "/<clID>[^<]*<\/clID>/i";
    $to[] = '<clID>Not disclosed clID</clID>';
    $from[] = "/<pw>[^<]*<\/pw>/i";
    $to[] = '<pw>Not disclosed pw</pw>';
    $sendforlog = preg_replace($from, $to, $send);

    if (function_exists("logModuleCall")) {
        logModuleCall(OKEPP_MODULE, $action, $sendforlog, $responsedata);
    }
}
