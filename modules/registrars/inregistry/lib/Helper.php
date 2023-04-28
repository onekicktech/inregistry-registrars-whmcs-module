<?php

function ok_epp_log($action, $data = false, $force = false)
{
    if ($force === false && OKEPP_DEBUG_MODE !== true) {
        return true;
    }

    $path = defined("LOGS_DIR") ? LOGS_DIR . '/epp_activity.log' : '../epp_activity.log';
    ob_start();
    echo "<!-- ================= $action ================= -->\n\n";
    if (is_array($data)) {
        $data = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
    echo $data;
    echo "\n\n\n";
    $content = ob_get_contents();
    ob_end_clean();
    file_put_contents($path, $content, FILE_APPEND);
}

function ok_epp_line2arr(string $str, $limit = PHP_INT_MAX)
{
    return ok_epp_arrTrim(explode("\n", trim($str), $limit));
}

function ok_epp_arrTrim(array $arr)
{
    return array_map('trim', $arr);
}

function ok_epp_arr2arr(array $arr)
{
    if (isset($arr[0])) {
        $array = $arr;
    } else {
        $array[] = $arr;
    }

    return $array;
}

function ok_epp_pr($data, $type = 0)
{
    if (is_array($data) || is_object($data)) {
        echo '<pre>';
        print_r($data);
        echo '</pre>';
    } else {
        echo $data;
    }

    if ($type != 0) {
        exit();
    } else {
        echo '<hr>';
    }
}

function ok_epp_xml2array($contents, $get_attributes = 1, $priority = "tag")
{
    $type = $tag = "";
    $level = 0;
    $parser = xml_parser_create("");
    xml_parser_set_option($parser, XML_OPTION_TARGET_ENCODING, "UTF-8");
    xml_parser_set_option($parser, XML_OPTION_CASE_FOLDING, 0);
    xml_parser_set_option($parser, XML_OPTION_SKIP_WHITE, 1);
    xml_parse_into_struct($parser, trim($contents), $xml_values);
    xml_parser_free($parser);
    if (!$xml_values) {
        return null;
    }
    $xml_array = [];
    $parents = [];
    $opened_tags = [];
    $arr = [];
    $current = &$xml_array;
    $repeated_tag_index = [];
    foreach ($xml_values as $data) {
        unset($attributes);
        unset($value);
        extract($data);
        $result = [];
        $attributes_data = [];
        if (isset($value)) {
            if ($priority === "tag") {
                $result = $value;
            } else {
                $result["value"] = $value;
            }
        }
        if (isset($attributes) && $get_attributes) {
            foreach ($attributes as $attr => $val) {
                if ($priority === "tag") {
                    $attributes_data[$attr] = $val;
                } else {
                    $result["attr"][$attr] = $val;
                }
            }
        }
        if ($type === "open") {
            $parent[$level - 1] = &$current;
            if (!is_array($current) || !in_array($tag, array_keys($current))) {
                $current[$tag] = $result;
                if ($attributes_data) {
                    $current[$tag . "_attr"] = $attributes_data;
                }
                $repeated_tag_index[$tag . "_" . $level] = 1;
                $current = &$current[$tag];
            } else {
                if (isset($current[$tag][0])) {
                    $current[$tag][$repeated_tag_index[$tag . "_" . $level]] = $result;
                    $repeated_tag_index[$tag . "_" . $level]++;
                } else {
                    $current[$tag] = [$current[$tag], $result];
                    $repeated_tag_index[$tag . "_" . $level] = 2;
                    if (isset($current[$tag . "_attr"])) {
                        $current[$tag]["0_attr"] = $current[$tag . "_attr"];
                        unset($current[$tag . "_attr"]);
                    }
                }
                $last_item_index = $repeated_tag_index[$tag . "_" . $level] - 1;
                $current = &$current[$tag][$last_item_index];
            }
        } else {
            if ($type === "complete") {
                if (!isset($current[$tag])) {
                    $current[$tag] = $result;
                    $repeated_tag_index[$tag . "_" . $level] = 1;
                    if ($priority === "tag" && $attributes_data) {
                        $current[$tag . "_attr"] = $attributes_data;
                    }
                } else {
                    if (isset($current[$tag][0]) && is_array($current[$tag])) {
                        $current[$tag][$repeated_tag_index[$tag . "_" . $level]] = $result;
                        if ($priority === "tag" && $get_attributes && $attributes_data) {
                            $current[$tag][$repeated_tag_index[$tag . "_" . $level] . "_attr"] = $attributes_data;
                        }
                        $repeated_tag_index[$tag . "_" . $level]++;
                    } else {
                        $current[$tag] = [$current[$tag], $result];
                        $repeated_tag_index[$tag . "_" . $level] = 1;
                        if ($priority === "tag" && $get_attributes) {
                            if (isset($current[$tag . "_attr"])) {
                                $current[$tag]["0_attr"] = $current[$tag . "_attr"];
                                unset($current[$tag . "_attr"]);
                            }
                            if ($attributes_data) {
                                $current[$tag][$repeated_tag_index[$tag . "_" . $level] . "_attr"] = $attributes_data;
                            }
                        }
                        $repeated_tag_index[$tag . "_" . $level]++;
                    }
                }
            } else {
                if ($type === "close") {
                    $current = &$parent[$level - 1];
                }
            }
        }
    }
    return $xml_array;
}

function ok_epp_simple_ArrStrTag($data, $inTag = null, $func = false)
{
    $return = "";
    if (empty($data)) {
    } elseif (is_array($data) && count($data) > 0) {
        foreach ($data as $v) {
            if (!empty($v)) {
                $fv = $func === false ? htmlspecialchars($v) : htmlspecialchars($func($v));
                $return .= $inTag === null ? $fv : '<' . $inTag . '>' . $fv . '</' . $inTag . '>';
            }
        }
    } else {
        $fv = $func === false ? htmlspecialchars($data) : htmlspecialchars($func($data));
        $return = $inTag === null ? $fv : '<' . $inTag . '>' . $fv . '</' . $inTag . '>';
    }
    return $return;
}

function ok_epp_simple_IpsArrStrTag($data, $inTag)
{
    $ip = "";
    if (is_array($data) && count($data) > 0) {
        foreach ($data as $v) {
            if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip .= '<' . $inTag . ' ip="v4">' . $v . '</' . $inTag . '>';
            } elseif (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ip .= '<' . $inTag . ' ip="v6">' . $v . '</' . $inTag . '>';
            }
        }
    } else {
        if (filter_var($data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip .= '<' . $inTag . ' ip="v4">' . $data . '</' . $inTag . '>';
        } elseif (filter_var($data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip .= '<' . $inTag . ' ip="v6">' . $data . '</' . $inTag . '>';
        }
    }
    return $ip;
}

function ok_epp_generateObjectPW($objType = 'none')
{
    $result = '';
    $uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    $numbers = "1234567890";
    $specialSymbols = "!=+-";
    $minLength = 16;
    $maxLength = 16;
    $length = mt_rand($minLength, $maxLength);

    // Include at least one character from each set
    $result .= $uppercaseChars[mt_rand(0, strlen($uppercaseChars) - 1)];
    $result .= $lowercaseChars[mt_rand(0, strlen($lowercaseChars) - 1)];
    $result .= $numbers[mt_rand(0, strlen($numbers) - 1)];
    $result .= $specialSymbols[mt_rand(0, strlen($specialSymbols) - 1)];

    // Append random characters to reach the desired length
    while (strlen($result) < $length) {
        $chars = $uppercaseChars . $lowercaseChars . $numbers . $specialSymbols;
        $result .= $chars[mt_rand(0, strlen($chars) - 1)];
    }

    return $result;
}

// prevent double encoding (&)
function ok_epp_htmlspecialchars($str)
{
    return htmlspecialchars(htmlspecialchars_decode($str));
}

function ok_epp_indexToName($data, string $idKeyName, string $idParam = "id"): array
{
    if (!empty($data) && count($data) > 0) {
        $sv = [];
        foreach ($data as $nid) {
            if (isset($nid[$idKeyName])) {
                $svv = [$idParam . $nid[$idKeyName] => $nid];
                $sv = array_merge($sv, $svv);
            }
        }
        if (!empty($sv)) {
            return $sv;
        } else {
            return $data;
        }
    } else {
        return [];
    }
}

function ok_epp_generateRandomString($length = 12)
{
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}

function ok_epp_startEppClient(array $config)
{
    try {
        $eppCon = new EppClient(ok_epp_buildConfig($config));
        $eppCon->login($config['clid'], $config['pw']);
        return $eppCon;
    } catch (exception $e) {
        return (object) ["error" => $e->getMessage()];
    }
}

function ok_epp_GetNameservers(array $config, string $domainName)
{
    if (empty($domainName)) {
        return ["error" => "Empty Domain Name"];
    }

    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $dInfo = $con->domainInfo($domainName);
        $return = $dInfo['domain']['ns'];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_SaveNameservers(array $config, string $domainName, array $saveNSD)
{
    if (empty($domainName)) {
        return ["error" => "Empty Domain Name"];
    }

    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        if (!empty($saveNSD)) {
            $dInfo = $con->domainInfo($domainName);
            $remNSD = $dInfo['domain']['ns'];

            $remNS = array_diff($remNSD, $saveNSD);
            $saveNS = array_diff($saveNSD, $remNSD);

            if (!empty($remNS) || !empty($saveNS)) {
                $nsSave = $con->domainUpdateNS($domainName, $saveNS, $remNS);
                $return = ["success" => $nsSave['domain']['success']];
            } else {
                $return = ["success" => true];
            }
        } else {
            $return = ["error" => "Empty Save Nameservers"];
        }
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_GetRegistrarLock(array $config, string $domainName)
{
    if (empty($domainName)) {
        return ["error" => "Empty Domain Name"];
    }

    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $dInfo = $con->domainInfo($domainName);
        $return = in_array('clientTransferProhibited', $dInfo['domain']['status']) ? 'locked' : 'unlocked';
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_SaveRegistrarLock(array $config, string $domainName, $lockenabled)
{
    if (empty($domainName)) {
        return ["error" => "Empty Domain Name"];
    }

    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $status = [
            //'clientUpdateProhibited',
            //'clientDeleteProhibited',
            'clientTransferProhibited',
        ];

        $actionSt = $lockenabled == 'locked' ? 'add' : 'rem';
        $sUp = $con->domainUpdateStatus($domainName, $status, $actionSt);

        $return = ["success" => $sUp['domain']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_RegisterDomain(array $config, string $domainName, array $nss)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        //check tld
        if (isset($config['tld'])) {
            $suTld = ok_epp_gTld();
            if (!in_array(('.' . $config['tld']), $suTld['ccTLD'])) {
                throw new exception("Domain Zone Invalid. We not support Tld is {$config['tld']}");
            }
        }

        //check domain
        $ckDomain = $con->domainCheck($domainName);
        if ($ckDomain['domain'][0]['status'] != 'available') {
            throw new exception("Domain is not available");
        }

        //check contacts
        //create contacts
        $contents = [
            'registrant',
            'admin',
            'tech',
            'billing',
        ];

        $unqContactId = ok_epp_generateUniqueContactId($con, $config['identityprefix'], $config['domainid']);
        $crContact = $con->contactCreate($unqContactId, $config);

        $cids = [];
        foreach ($contents as $contactType) {
            $cids[$contactType] = $unqContactId;
        }

        //nameserver host check
        //nameserver host create
        if (!empty($nss)) {
            $ckNs = $con->hostCheck($nss);
            $hoCrete = [];
            foreach ($ckNs['host'] as $hov) {
                if ($hov['avail'] == 1) {
                    $hoCrete[] = $con->hostCreate($hov['name']);
                }
            }
        }

        $periodYr = is_numeric($config['regperiod']) ? $config['regperiod'] : 1;

        $doCreate = $con->domainCreate($domainName, $periodYr, $cids, $nss);
        $con->domainUpdateStatus($domainName, 'clientTransferProhibited', 'add');

        $return = ["success" => $doCreate['domain']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_generateUniqueContactId($eppCon, $identityprefix, $dId)
{
    $unqContactId = strtoupper($identityprefix . '_' . ok_epp_generateRandomString(4) . '' . $dId);
    $cci = $eppCon->contactCheck($unqContactId);
    if ($cci['contact'][0]['avail'] == 1) {
        return $unqContactId;
    } else {
        return ok_epp_generateUniqueContactId($eppCon, $identityprefix, $dId);
    }
}

function ok_epp_TransferDomain(array $config, string $domainName, string $transferSecret)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        ///Pending -> domainInfo add and verify status (locked or not) and also verify trasferSecret code

        //$periodYr = is_numeric($config['regperiod']) ? $config['regperiod'] : 1; //remove -> its only 1 year support
        $trDonain = $con->domainTransfer($domainName, 'request', $transferSecret);
        $return = ["success" => $trDonain['domain']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_RenewDomain(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $periodYr = is_numeric($config['regperiod']) ? $config['regperiod'] : 1;
        $reDonain = $con->domainRenew($domainName, $periodYr);
        $return = ["success" => $reDonain['domain']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_GetContactDetails(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $cccData = $con->domainContactInfo($domainName, true);
        $return = $cccData['contents'];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_SaveContactDetails(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        if (!isset($config['contactdetails'])) {
            throw new exception("contact details Empty");
        }

        $cccData = $con->domainContactInfo($domainName);

        $ccvvvAsign = $cccData['cId'];
        foreach ($cccData['cId'] as $cdkey => $cdvalue) {
            $params = [];

            $getContact = $cccData['contents'][ucfirst($cdkey)];
            $savContact = $config['contactdetails'][ucfirst($cdkey)];

            unset($savContact['Phone Country Code']);
            unset($savContact['phone-normalised']);

            if ($savContact != $getContact) {
                $params["firstname"] = $savContact['Full Name'];
                $params["email"] = $savContact['Email'];
                $params["companyname"] = $savContact['Company Name'];
                $params["address1"] = $savContact['Address 1'];
                $params["address2"] = $savContact['Address 2'];
                $params["address3"] = ($savContact['Address 3'] ?? '');
                $params["city"] = $savContact['City'];
                $params["state"] = $savContact['State'];
                $params["postcode"] = $savContact['Postcode'];
                $params["country"] = $savContact['Country'];
                $params["fullphonenumber"] = $savContact['Phone Number'];

                unset($ccvvvAsign[$cdkey]);
                if (in_array($cdvalue, $ccvvvAsign)) {
                    $cdkvCI = ok_epp_generateUniqueContactId($con, $config['identityprefix'], $config['domainid']);
                    $ccvvvAsign[$cdkey] = $cdkvCI;
                    $crCC = $con->contactCreate($cdkvCI, $params);
                    if ($crCC['contact']['success']) {
                        $con->domainUpdateContact($domainName, $cdkey, $cdkvCI, $cdvalue);
                    }
                } else {
                    $ccvvvAsign[$cdkey] = $cdvalue;
                    $con->contactUpdate($cdvalue, $params);
                }
            }
        }

        $return = ["success" => true];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_GetEPPCode(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $cccData = $con->domainInfo($domainName);
        if (empty($cccData['domain']['authInfo'])) {
            throw new exception("Invalid Domain");
        }

        $return = ["eppcode" => $cccData['domain']['authInfo']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_RegisterNameserver(array $config)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        if (empty($config['nameserver']) || empty($config['ipaddress'])) {
            throw new exception("Empty required parameters values");
        }

        $nameserver = $config['nameserver'];
        $ip = $config['ipaddress'];

        $ckNs = $con->hostCheck($nameserver);
        if ($ckNs['host'][0]['avail'] == 1) {
            $creHost = $con->hostCreate($nameserver, $ip);
            $return = ["success" => $creHost['host']['success']];
        } else {
            $return = ["success" => true];
        }
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_ModifyNameserver(array $config)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        if (empty($config['nameserver']) || empty($config['currentipaddress']) || empty($config['newipaddress'])) {
            throw new exception("Empty required parameters values");
        }
        $ckNs = $con->hostUpdate($config['nameserver'], $config['newipaddress'], $config['currentipaddress']);
        $return = ["success" => $ckNs['host']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_DeleteNameserver(array $config)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        if (empty($config['nameserver'])) {
            throw new exception("Empty required parameters values");
        }
        $ckNs = $con->hostDelete($config['nameserver']);
        $return = ["success" => $ckNs['host']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_RequestDelete(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $del = $con->domainDelete($domainName);
        $return = ["success" => $del['domain']['success']];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_IDProtectToggle(array $config, string $domainName, $protectenable)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $dInfo = $con->domainInfo($domainName);
        $contents = [];
        $contents['registrant'] = $dInfo['domain']['registrant'];
        foreach ($dInfo['domain']['contact'] as $dKey => $dValue) {
            $contents[$dKey] = $dValue;
        }

        $ucIds = array_unique(array_values($contents));
        $cidData = [];
        foreach ($ucIds as $civalue) {
            $cidData = $con->contactUpdateProtect($civalue, $protectenable);
        }

        //return $cidData;
        $return = ["success" => true];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_SyncDomain(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $dInfo = $con->domainInfo($domainName);

        $expDate = $dInfo['domain']['exDate'];
        if (empty($expDate)) {
            throw new exception('Empty expDate date for domain: ' . $domainName);
        }

        $timestamp = strtotime($expDate);
        if ($timestamp < time()) {
            $return = ["expired" => true, "expirydate" => date("Y-m-d", $timestamp)];
        } else {
            $return = ["active" => true, "expirydate" => date("Y-m-d", $timestamp)];
        }
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_TransferDomainSync(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $dInfo = $con->domainTransfer($domainName, "query");
        $trStatus = $dInfo['domain']['trStatus'];
        $expDate = $dInfo['domain']['exDate'];

        switch ($trStatus) {
            case 'pending':
                $return['completed'] = false;
                break;
            case 'clientApproved':
            case 'serverApproved':
                $return['completed'] = true;
                $return['expirydate'] = date('Y-m-d', is_numeric($expDate) ? $expDate : strtotime($expDate));
                break;
            case 'clientRejected':
            case 'clientCancelled':
            case 'serverCancelled':
                $return['failed'] = true;
                $return['reason'] = $trStatus;
                break;
            default:
                $return = [
                    'error' => sprintf('invalid transfer status: %s', $trStatus),
                ];
                break;
        }

        if ($return['completed'] === true) {
            $newContactId = ok_epp_generateUniqueContactId($con, $config['identityprefix'], $config['domainid']);
            $crCC = $con->contactCreate($newContactId, $config);
            if ($crCC['contact']['success']) {
                $con->domainTransferUpdate($domainName, $newContactId);
            }
        }
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_cancelDomainTransfer(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $con->domainTransfer($domainName, "cancel");
        $return = ["message" => "Successfully cancelled the domain transfer"];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_ep_AuthinfoUpdate(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $con->domainUpdateAuthinfo($domainName, ok_epp_generateObjectPW());
        $return = ["success" => true, "message" => "Successfully Changed EPP code"];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}

function ok_epp_GetDomainInformation(array $config, string $domainName)
{
    $con = ok_epp_startEppClient($config);
    if (!empty($con->error)) {
        return (array) $con;
    }

    try {
        $dInfo = $con->domainInfo($domainName);
        $return = $dInfo['domain'];
    } catch (exception $e) {
        $return = ["error" => $e->getMessage()];
    }

    if (!empty($con)) {
        $con->logout();
    }

    return $return;
}
