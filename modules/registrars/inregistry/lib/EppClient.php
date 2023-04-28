<?php

class EppClient
{
    private $config;
    private $params;
    private $socket = null;
    private $isLogined = false;

    public function __construct($config)
    {
        $this->config = $config;
        $this->connect();
    }

    // function __destruct()
    // {
    // 	$this->logout();
    // }


    public function getConfig($key)
    {
        if (isset($this->config[$key])) {
            return $this->config[$key];
        } else {
            throw new exception("Configuration Undeclared Parameters: {$key} ");
        }
    }

    public function getParams($key)
    {
        if (isset($this->params[$key])) {
            return $this->params[$key];
        } else {
            throw new exception("Undeclared Parameters: {$key} ");
        }
    }

    public function setParams($params)
    {
        $this->params = $params;
    }

    public function connect($timeout = 30)
    {
        $errmsg = "";
        $errno = 0;

        $host = $this->getConfig('host');
        $port = $this->getConfig('port');
        $tls_version = $this->getConfig('tls_version');
        $opts = [
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'verify_host' => false,
                'local_cert' => $this->getConfig('local_cert'),
                'local_pk' => $this->getConfig('local_pk'),
                'passphrase' => $this->getConfig('passphrase'),
                'allow_self_signed' => true
            ]
        ];

        $target = "tlsv{$tls_version}://{$host}:{$port}";

        $context = stream_context_create($opts);
        $this->socket = stream_socket_client($target, $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);

        if (!is_resource($this->socket)) {
            throw new exception("Connecting to " . $target . ". <p>The error message was '" . $errmsg . "' (code " . $errno . ")");
            fclose($this->socket);
        }

        $this->read("connect");
        return true;
    }

    public function login($usr, $pwd, $newPwd = null)
    {
        $from = $to = [];
        $from[] = '/{{ clID }}/';
        //$to[] = htmlspecialchars($usr);
        $to[] = '<clID>' . htmlspecialchars($usr) . '</clID>';

        $from[] = '/{{ pw }}/';
        $to[] = '<pw>' . ok_epp_htmlspecialchars($pwd) . '</pw>';

        $from[] = '/{{ newPW }}/';
        $to[] = $newPwd === null ? '' : '<newPW>' . ok_epp_htmlspecialchars($newPwd) . '</newPW>';


        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-login-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <login>
            {{ clID }}
            {{ pw }}
            {{ newPW }}
            <options>
                <version>1.0</version>
                <lang>en</lang>
            </options>
            <svcs>
                <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
                <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
                <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
                <svcExtension>
                    <extURI>urn:ietf:params:xml:ns:idn-1.0</extURI>
                    <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
                </svcExtension>
            </svcs>
        </login>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');
        $r = $this->_write($xml, __FUNCTION__);
        $this->isLogined = true;
        return true;
    }

    public function changePassword($usr, $pwd, $newPwd)
    {
        return $this->login($usr, $pwd, $newPwd);
    }

    public function logout()
    {
        if (!$this->isLogined) {
            return true;
        }

        $from = $to = [];
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-logout-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <logout />
        <clTRID>{{ clTRID }}</clTRID>
    </command>');
        $r = $this->_write($xml, __FUNCTION__);
        $this->disconnect();
        $this->isLogined = false;
        return true;
    }

    public function read($action)
    {
        //ok_epp_log($action . '-this', $this);

        $hdr = stream_get_contents($this->socket, 4);
        if ($hdr === false) {
            throw new exception('Connection appears to have closed.');
        }
        if (strlen($hdr) < 4) {
            throw new exception('Failed to read header from the connection.');
        }

        $unpacked = unpack('N', $hdr);
        $xml = fread($this->socket, ($unpacked[1] - 4));
        $xml = preg_replace('/></', ">\n<", $xml);

        ok_epp_log($action . '-response', $xml);

        return $xml;
    }

    public function disconnect()
    {
        $result = fclose($this->socket);
        if (!$result) {
            throw new exception('Error closing the connection.');
        }
        $this->socket = null;
        return $result;
    }

    public function _write($xml, $action = 'Unknown', $fullXml = false)
    {
        //ok_epp_log($action . '-send-this', $this);
        if ($fullXml === false) {
            $xml = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
            <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">' . $xml . '</epp>';
        }


        ok_epp_log($action . '-command', $xml);

        if (fwrite($this->socket, pack('N', (strlen($xml) + 4)) . $xml) === false) {
            throw new exception('Error writing to the connection.');
        }
        $response = $this->read($action);
        if (function_exists(("ok_epp_modulelog"))) {
            ok_epp_modulelog($xml, $response, $action);
        }

        $r = ok_epp_xml2array($response);
        if (isset($r['epp']['response']['result_attr']) && ($r['epp']['response']['result_attr']['code'] >= 2000)) {
            throw new exception($r['epp']['response']['result']['msg'] . ': ' . $r['epp']['response']['result']['extValue']['reason']);
        }
        return isset($r['epp']['response']) ? $r['epp']['response'] : $r;
    }

    //Domain Operations -> all commands as described in RFC 5731 and RFC 3915
    //Extended domain availability check
    public function domainCheck($domainNames)
    {
        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = ok_epp_simple_ArrStrTag($domainNames, "name");
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <check>
            <check xmlns="urn:ietf:params:xml:ns:domain-1.0">
                {{ name }}
            </check>
        </check>
        <extension>
            <check xmlns="urn:ar:params:xml:ns:exAvail-1.0" />
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $result = [];
        foreach (ok_epp_arr2arr($r['extension']['chkData']['cd']) as $dList) {
            $result[] = [
                "name" => $dList['name'],
                "status" => $dList['state_attr']['s'],
                "reason" => isset($dList['state']['reason']) ? $dList['state']['reason'] : "",
            ];
        }
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    //Domain price check
    public function domainPriceCheck($domainNames)
    {
        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = ok_epp_simple_ArrStrTag($domainNames, "name");
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-price-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
    <check>
        <check xmlns="urn:ietf:params:xml:ns:domain-1.0">
            {{ name }}
        </check>
    </check>
    <extension>
        <check xmlns="urn:ar:params:xml:ns:price-1.2">
            <period unit="y">1</period>
        </check>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
</command>');

        $r = $this->_write($xml, __FUNCTION__);
        $result = [];
        foreach (ok_epp_arr2arr($r['extension']['chkData']['cd']) as $dList) {
            if (isset($dList['reason'])) {
                $result[] = [
                    "name" => $dList['name'],
                    "reason" => $dList['reason']
                ];
            } else {
                $result[] = [
                    "name" => $dList['name'],
                    "category" => $dList['category'],
                    "period" => $dList['period'],
                    "period_unit" => $dList['period_attr']['unit'],
                    "createPrice" => $dList['createPrice'],
                    "renewPrice" => $dList['renewPrice'],
                    "restorePrice" => $dList['restorePrice'],
                    "transferPrice" => $dList['transferPrice'],
                ];
            }
        }
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    //Domain Claims Check
    public function domainClaimsCheck($domainNames)
    {
        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = ok_epp_simple_ArrStrTag($domainNames, "name");
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-claims-check-' . $clTRID);

        $xml = preg_replace($from, $to, '<command>
        <check>
            <check xmlns="urn:ietf:params:xml:ns:domain-1.0">
                {{ name }}
            </check>
        </check>
        <extension>
            <check xmlns="urn:ar:params:xml:ns:tmch-1.0" />
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $result = [];
        foreach (ok_epp_arr2arr($r['extension']['chkData']['cd']) as $dList) {
            $result[] = [
                "name" => $dList['name'],
                "claim" => $dList['name_attr']['claim'],
                "key" => isset($dList['key']) ? $dList['key'] : ""
            ];
        }
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    ////domain, price, claims check
    public function domainCheck_Enhanced($domainNames, $priceCheck = false, $claimsCheck = false)
    {
        $priceEx = '';
        if ($priceCheck !== false) {
            $period = is_numeric($priceCheck) ? $priceCheck : 1;
            $priceEx = '<check xmlns="urn:ar:params:xml:ns:price-1.2"><period unit="y">' . $period . '</period></check>';
        }

        $claimsEx = '';
        if ($claimsCheck !== false) {
            $claimsEx = '<check xmlns="urn:ar:params:xml:ns:tmch-1.0" />';
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = ok_epp_simple_ArrStrTag($domainNames, "name");

        $from[] = '/{{ priceEx }}/';
        $to[] = $priceEx;

        $from[] = '/{{ claimsEx }}/';
        $to[] = $claimsEx;

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-price-claims-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <check>
            <check xmlns="urn:ietf:params:xml:ns:domain-1.0">
                {{ name }}
            </check>
        </check>
        <extension>
            <check xmlns="urn:ar:params:xml:ns:exAvail-1.0" />
            {{ priceEx }}
            {{ claimsEx }}
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $result = [];
        foreach ($r['extension']['chkData'] as $dLists) {
            if (isset($dLists['cd'])) {
                foreach (ok_epp_arr2arr($dLists['cd']) as $dList) {
                    if (isset($dList['state_attr']['s'])) {
                        $result[$dList['name']]['check'] = [
                            "name" => $dList['name'],
                            "status" => $dList['state_attr']['s'],
                            "reason" => isset($dList['state']['reason']) ? $dList['state']['reason'] : "",
                        ];
                    }

                    if (isset($dList['createPrice'])) {
                        if (isset($dList['reason'])) {
                            $result[$dList['name']]['price'] = [
                                "name" => $dList['name'],
                                "reason" => $dList['reason']
                            ];
                        } else {
                            $result[$dList['name']]['price'] = [
                                "name" => $dList['name'],
                                "category" => $dList['category'],
                                "period" => $dList['period'],
                                "period_unit" => $dList['period_attr']['unit'],
                                "createPrice" => $dList['createPrice'],
                                "renewPrice" => $dList['renewPrice'],
                                "restorePrice" => $dList['restorePrice'],
                                "transferPrice" => $dList['transferPrice'],
                            ];
                        }
                    }

                    if (isset($dList['name_attr']['claim'])) {
                        $result[$dList['name']]['claim'] = [
                            "name" => $dList['name'],
                            "claim" => $dList['name_attr']['claim'],
                            "key" => isset($dList['key']) ? $dList['key'] : ""
                        ];
                    }
                }
            }
        }
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    public function domainCreate($domainName, $periodYr, $contacts, $ns, $authInfo = null)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }
        $authInfo = $authInfo === null ? ok_epp_generateObjectPW() : $authInfo;

        $contactsXml = "";
        if (!empty($contacts)) {
            foreach ($contacts as $contactType => $contactID) {
                if ($contactType == 'registrant') {
                    $contactsXml .= '<domain:registrant>' . $contactID . '</domain:registrant>';
                } else {
                    $contactsXml .= '<domain:contact type="' . $contactType . '">' . $contactID . '</domain:contact>' . "\n";
                }
            }
        }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ period }}/';
        $to[] = is_numeric($periodYr) ? $periodYr : 1;

        $from[] = '/{{ hostObjs }}/';
        $to[] = ok_epp_simple_ArrStrTag($ns, "domain:hostObj");

        $from[] = '/{{ contacts }}/';
        $to[] = $contactsXml;

        $from[] = '/{{ authInfoPw }}/';
        $to[] = htmlspecialchars($authInfo);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-create-' . $clTRID);

        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
    <create>
      <domain:create
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">{{ period }}</domain:period>
        <domain:ns>
          {{ hostObjs }}
        </domain:ns>
        {{ contacts }}
        <domain:authInfo>
          <domain:pw>{{ authInfoPw }}</domain:pw>
        </domain:authInfo>
      </domain:create>
    </create>
    <clTRID>{{ clTRID }}</clTRID>
  </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['domain:creData'];
        $result = [
            "success" => true,
            "name" => $dList['domain:name'],
            "crDate" => $dList['domain:crDate'],
            "exDate" => $dList['domain:exDate'],
        ];

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    public function domainTransfer($domainName, $oprationType, $authInfo = "")
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }
        if (!in_array($oprationType, ['request', 'query', 'cancel', 'reject', 'approve'])) {
            throw new exception('Invalid value for transfer:op specified.');
        }
        if ($oprationType == "request" && empty($authInfo)) {
            throw new exception('Invalid value for authInfo.');
        }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ type }}/';
        $to[] = htmlspecialchars($oprationType);

        if ($oprationType === "request") {
            $from[] = '/{{ periodYr }}/';
            $periodYr = 1;
            $to[] = '<domain:period unit="y">' . $periodYr . '</domain:period>';

            $from[] = '/{{ authInfo }}/';
            $to[] = !empty($authInfo) ? '<domain:authInfo><domain:pw>' . ok_epp_htmlspecialchars($authInfo) . '</domain:pw></domain:authInfo>' : "";
        } else {
            $from[] = '/{{ periodYr }}/';
            $to[] = "";

            $from[] = '/{{ authInfo }}/';
            $to[] = "";
        }

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-transfer-' . $oprationType . '-' . $clTRID);

        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
				<transfer op="{{ type }}">
				  <domain:transfer
				   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
					<domain:name>{{ name }}</domain:name>
					{{ periodYr }}
					{{ authInfo }}
				  </domain:transfer>
				</transfer>
				<clTRID>{{ clTRID }}</clTRID>
			  </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['domain:trnData'];
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $dList['domain:name'],
                "trStatus" => ($dList['domain:trStatus'] ?? ''),

                "reID" => $dList['domain:reID'],
                "reDate" => $dList['domain:reDate'],
                "acID" => $dList['domain:acID'],
                "acDate" => $dList['domain:acDate'],
                "exDate" => $dList['domain:exDate'],
            ]

        ];

        return $return;
    }

    public function domainRenew($domainName, $periodYr = 1, $exDate = null)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        if ($exDate === null) {
            $dd =  $this->domainInfo($domainName);
            $exDate = $dd['domain']['exDate'];
        }
        $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $exDate);

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);
        $from[] = '/{{ regperiod }}/';
        $to[] = is_numeric($periodYr) ? $periodYr : 1;

        $from[] = '/{{ expDate }}/';
        $to[] = htmlspecialchars($expDate);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-renew-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
	<renew>
	  <domain:renew
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
		<domain:name>{{ name }}</domain:name>
		<domain:curExpDate>{{ expDate }}</domain:curExpDate>
		<domain:period unit="y">{{ regperiod }}</domain:period>
	  </domain:renew>
	</renew>
	<clTRID>{{ clTRID }}</clTRID>
  </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['domain:renData'];
        $result = [
            "success" => true,
            "name" => $dList['domain:name'],
            "exDate" => $dList['domain:exDate'],
        ];

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    public function domainDelete($domainName)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-delete-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
	<delete>
	  <domain:delete
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
		<domain:name>{{ name }}</domain:name>
	  </domain:delete>
	</delete>
	<clTRID>{{ clTRID }}</clTRID>
  </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain Deleted"
            ]

        ];
        return $return;
    }

    public function domainRestore($domainName)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-restore-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
   <update>
	 <domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
	   <domain:name>{{ name }}</domain:name>
	   <domain:chg/>
	 </domain:update>
   </update>
   <extension>
	 <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0">
	   <rgp:restore op="request"/>
	 </rgp:update>
   </extension>
	<clTRID>{{ clTRID }}</clTRID>
  </command>');

        return $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "rgpStatus" => isset($r['extension']['upData']['rgpStatus_attr']['s']) ? $r['extension']['upData']['rgpStatus_attr']['s'] : "",
                "rgpDate" => isset($r['extension']['upData']['rgpStatus']) ? $r['extension']['upData']['rgpStatus'] : "",
                "msg" => "Domain Restored"
            ]

        ];
        return $return;
    }

    public function domainRestoreReport($domainName)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-restoreReport-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
	   <update>
		 <domain:update
		  xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
		  xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0
		  domain-1.0.xsd">
		   <domain:name>{{ name }}</domain:name>
		   <domain:chg/>
		 </domain:update>
	   </update>
	   <extension>
		 <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0"
		  xsi:schemaLocation="urn:ietf:params:xml:ns:rgp-1.0
		  rgp-1.0.xsd">
		   <rgp:restore op="report">
			 <rgp:report>
			   <rgp:preData>Pre-delete registration data goes here.
			   Both XML and free text are allowed.</rgp:preData>
			   <rgp:postData>Post-restore registration data goes here.
			   Both XML and free text are allowed.</rgp:postData>
			   <rgp:delTime>2019-10-10T22:00:00.0Z</rgp:delTime>
			   <rgp:resTime>2019-10-20T22:00:00.0Z</rgp:resTime>
			   <rgp:resReason>Registrant error.</rgp:resReason>
			   <rgp:statement>This registrar has not restored the
			   Registered Name in order to assume the rights to use
			   or sell the Registered Name for itself or for any
			   third party.</rgp:statement>
			   <rgp:statement>The information in this report is
			   true to best of this registrars knowledge, and this
			   registrar acknowledges that intentionally supplying
			   false information in this report shall constitute an
			   incurable material breach of the
			   Registry-Registrar Agreement.</rgp:statement>
			   <rgp:other>Supporting information goes
			   here.</rgp:other>
			 </rgp:report>
		   </rgp:restore>
		 </rgp:update>
	   </extension>
	<clTRID>{{ clTRID }}</clTRID>
	 </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain Restore Report"
            ]

        ];
        return $return;
    }

    public function domainInfo($domainName, $authInfo = null)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = $domainName;

        $from[] = '/{{ authInfo }}/';
        // $authInfo = ($authInfo === null ? '' : '<domain:authInfo><domain:pw><![CDATA['.htmlspecialchars($authInfo).']]></domain:pw></domain:authInfo>');
        $authInfo = ($authInfo === null ? '' : '<authInfo><pw>' . ok_epp_htmlspecialchars($authInfo) . '</pw></authInfo>');
        $to[] = $authInfo;

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-info-' . $clTRID);

        /*
        $commandXML = '<command>
        <info>
            <domain:info
                xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
                xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
                <domain:name hosts="all">{{ name }}</domain:name>
                {{ authInfo }}
                </domain:info>
        </info>
        <clTRID>{{ clTRID }}</clTRID>
    </command>';
    */

        $commandXML = '<command>
        <info>
            <info xmlns="urn:ietf:params:xml:ns:domain-1.0">
                <name>{{ name }}</name>
                {{ authInfo }}
            </info>
        </info>
        <clTRID>{{ clTRID }}</clTRID>
    </command>';

        $xml = preg_replace($from, $to, $commandXML);

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['domain:infData'];

        if (empty($dList['domain:status'])) {
            $dStatus = [$dList['domain:status_attr']['s']];
        } else {
            $dStatus = [];
            foreach ($dList['domain:status'] as $dStatusc) {
                if (isset($dStatusc['s'])) {
                    $dStatus[] = $dStatusc['s'];
                }
            }
        }

        $ns = [];
        if (isset($dList['domain:ns']['domain:hostObj'])) {
            $ns = $dList['domain:ns']['domain:hostObj'];
            sort($ns);
        }

        $host = [];
        if (isset($dList['domain:host'])) {
            $host = is_string($dList['domain:host']) ? [$dList['domain:host']] : $dList['domain:host'];
            sort($host);
        }

        $result = [
            "name" => $dList['domain:name'],
            "roid" => $dList['domain:roid'],
            "status" => is_string($dStatus) ? [$dStatus] : $dStatus,
            "registrant" => $dList['domain:registrant'],
            "contact" => [
                $dList['domain:contact']["0_attr"]["type"] => $dList['domain:contact']["0"],
                $dList['domain:contact']["1_attr"]["type"] => $dList['domain:contact']["1"],
                $dList['domain:contact']["2_attr"]["type"] => $dList['domain:contact']["2"]
            ],
            "ns" => $ns,
            "host" => $host,
            "clID" => $dList['domain:clID'],
            "crID" => $dList['domain:crID'],
            "upID" => isset($dList['domain:upID']) ? $dList['domain:upID'] : "",
            "upDate" => isset($dList['domain:upDate']) ? $dList['domain:upDate'] : "",
            "crDate" => $dList['domain:crDate'],
            "exDate" => ($dList['domain:exDate'] ?? ''),
            "trDate" => isset($dList['domain:trDate']) ? $dList['domain:trDate'] : "",

            "authInfo" => ($dList['domain:authInfo']['domain:pw'] ?? ''),
        ];

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => $result

        ];
        return $return;
    }

    public function domainUpdateNS($domainName, $addNS = null, $remNS = null)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $remNSXML = ok_epp_simple_ArrStrTag($remNS, "domain:hostObj");
        $addNSXML = ok_epp_simple_ArrStrTag($addNS, "domain:hostObj");

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ addNS }}/';
        $to[] = !empty($addNSXML) ? '<domain:add><domain:ns>' . $addNSXML . '</domain:ns></domain:add>' : "";

        $from[] = '/{{ remNS }}/';
        $to[] = !empty($remNSXML) ? '<domain:rem><domain:ns>' . $remNSXML . '</domain:ns></domain:rem>' : "";

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-updateNS-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <update>
            <domain:update
                xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
                xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
                <domain:name>{{ name }}</domain:name>
                {{ addNS }}
                {{ remNS }}
                </domain:update>
        </update>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain NS Updated"
            ]

        ];
        return $return;
    }

    public function domainTransferUpdate($domainName, $newContactId)
    {
        $chgXML = $addXML = $remXML = "";

        $dInfo = $this->domainInfo($domainName);
        if (in_array('pendingTransfer', $dInfo['domain']['status'])) {
            throw new exception('Invalid Request');
        }

        // start tag
        $chgXML .= '<domain:chg>' . "\n";
        $addXML .= '<domain:add>' . "\n";
        $remXML .= '<domain:rem>' . "\n";


        // contact update
        $chgXML .= '<domain:registrant>' . htmlspecialchars($newContactId) . '</domain:registrant>' . "\n";
        foreach ($dInfo['domain']['contact'] as $contactType => $oldContactId) {
            $addXML .= '<domain:contact type="' . htmlspecialchars($contactType) . '">' . htmlspecialchars($newContactId) . '</domain:contact>' . "\n";
            $remXML .= '<domain:contact type="' . htmlspecialchars($contactType) . '">' . htmlspecialchars($oldContactId) . '</domain:contact>' . "\n";
        }

        if (in_array('ok', $dInfo['domain']['status'])) {
            // Registrar trasfer Lock Update
            $addXML .= '<domain:status s="clientTransferProhibited"></domain:status>' . "\n";
        }

        // Password (AuthInfo) Update
        $chgXML .= '<domain:authInfo><domain:pw>' . htmlspecialchars(ok_epp_generateObjectPW()) . '</domain:pw></domain:authInfo>' . "\n";


        // end tag
        $chgXML .= '</domain:chg>' . "\n";
        $addXML .= '</domain:add>' . "\n";
        $remXML .= '</domain:rem>' . "\n";


        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ add }}/';
        $to[] = $addXML;
        $from[] = '/{{ rem }}/';
        $to[] = $remXML;
        $from[] = '/{{ chg }}/';
        $to[] = $chgXML;

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-domainTransferUpdate-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
   <update>
     <domain:update
		   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
		   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
       <domain:name>{{ name }}</domain:name>
       {{ add }}
       {{ rem }}
       {{ chg }}
     </domain:update>
   </update>
   <clTRID>{{ clTRID }}</clTRID>
 </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain Contact Updated"
            ]

        ];
        return $return;
    }

    public function domainUpdateContact($domainName, $contactType, $newContactId = null, $oldContactId = null)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain type');
        }

        if (!ok_epp_contactsType($contactType)) {
            throw new exception('Invalid Contact type');
        }
        $chgXML = $addXML = $remXML = "";
        if ($contactType === 'registrant') {
            $chgXML = '<domain:chg><domain:registrant>' . htmlspecialchars($newContactId) . '</domain:registrant></domain:chg>';
        } else {
            $addXML = $newContactId === null ? '' : '<domain:add><domain:contact type="' . htmlspecialchars($contactType) . '">' . htmlspecialchars($newContactId) . '</domain:contact></domain:add>';
            $remXML = $oldContactId === null ? '' : '<domain:rem><domain:contact type="' . htmlspecialchars($contactType) . '">' . htmlspecialchars($oldContactId) . '</domain:contact></domain:rem>';
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ add }}/';
        $to[] = $addXML;
        $from[] = '/{{ rem }}/';
        $to[] = $remXML;
        $from[] = '/{{ chg }}/';
        $to[] = $chgXML;

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-updateContact-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
   <update>
     <domain:update
		   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
		   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
       <domain:name>{{ name }}</domain:name>
       {{ add }}
       {{ rem }}
       {{ chg }}
     </domain:update>
   </update>
   <clTRID>{{ clTRID }}</clTRID>
 </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain Contact Updated"
            ]

        ];
        return $return;
    }

    public function domainUpdateStatus($domainName, $status, $command = "add")
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $addXML = '';
        if (!empty($status)) {
            $addXML .= ($command === 'add') ? '<domain:add>' : '<domain:rem>';
            if (is_array($status)) {
                foreach ($status as $sv) {
                    $addXML .= '<domain:status s="' . htmlspecialchars($sv) . '"></domain:status>';
                }
            } else {
                $addXML .= '<domain:status s="' . htmlspecialchars($status) . '"></domain:status>';
            }
            $addXML .= ($command === 'add') ? '</domain:add>' : '</domain:rem>';
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ addRem }}/';
        $to[] = $addXML;

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-updateStatus-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <update>
            <domain:update
                xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
                xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
                <domain:name>{{ name }}</domain:name>
                {{ addRem }}
                </domain:update>
        </update>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain Status Updated"
            ]

        ];
        return $return;
    }

    public function domainUpdateAuthinfo($domainName, $authInfo)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $from = $to = [];

        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ authInfo }}/';
        $to[] = ok_epp_htmlspecialchars($authInfo);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-updateStatus-' . $clTRID);

        $xml = preg_replace($from, $to, '<command>
   <update>
     <domain:update
		   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
		   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
       <domain:name>{{ name }}</domain:name>
       <domain:chg>
         <domain:authInfo>
           <domain:pw>{{ authInfo }}</domain:pw>
         </domain:authInfo>
       </domain:chg>
     </domain:update>
   </update>
   <clTRID>{{ clTRID }}</clTRID>
 </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain AuthInfo Updated"
            ]

        ];
        return $return;
    }

    //domainCreateDNSSEC pending
    public function domainUpdateDNSSEC($domainName, $command = "add", $params = [])
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        // $params = [
        //     'keyTag_1' => '33409',
        //     'alg_1' => '8',
        //     'digestType_1' => '1',
        //     'digest_1' => 'F4D6E26B3483C3D7B3EE17799B0570497FAF33BCB12B9B9CE573DDB491E16948'
        // ];

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);
        if ($command == 'add') {
            $from[] = '/{{ add }}/';
            $to[] = "<secDNS:add>
				<secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_1']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_1']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_1']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_1']) . "</secDNS:digest>
		  </secDNS:dsData>
		  </secDNS:add>";
            $from[] = '/{{ rem }}/';
            $to[] = "";
            $from[] = '/{{ addrem }}/';
            $to[] = "";
        } elseif ($command == 'rem') {
            $from[] = '/{{ add }}/';
            $to[] = "";
            $from[] = '/{{ rem }}/';
            $to[] = "<secDNS:rem>
				<secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_1']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_1']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_1']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_1']) . "</secDNS:digest>
		  </secDNS:dsData>
		  </secDNS:rem>";
            $from[] = '/{{ addrem }}/';
            $to[] = "";
        } elseif ($command == 'addrem') {
            $from[] = '/{{ add }}/';
            $to[] = "";
            $from[] = '/{{ rem }}/';
            $to[] = "";
            $from[] = '/{{ addrem }}/';
            $to[] = "<secDNS:rem>
				<secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_1']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_1']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_1']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_1']) . "</secDNS:digest>
		  </secDNS:dsData>
		  </secDNS:rem>
		  <secDNS:add>
		  <secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_2']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_2']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_2']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_2']) . "</secDNS:digest>
		  </secDNS:dsData>
		  </secDNS:add>";
        }

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-updateDNSSEC-' . $clTRID);

        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
        <update>
            <domain:update
                xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
                xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
                <domain:name>{{ name }}</domain:name>
            </domain:update>
        </update>
        <extension>
            <secDNS:update
                xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1"
                xsi:schemaLocation="urn:ietf:params:xml:ns:secDNS-1.1 secDNS-1.1.xsd">
                {{ add }}
                {{ rem }}
                {{ addrem }}
            </secDNS:update>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "domain" => [
                "success" => true,
                "name" => $domainName,
                "msg" => "Domain DNSSEC Updated"
            ]

        ];
        return $return;
    }


    public function domainCreateClaims($domainName, $params)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $nsXML = ok_epp_simple_ArrStrTag($params['ns'], "domain:hostObj");
        $contactsXml = "";
        if (!empty($params['contacts'])) {
            foreach ($params['contacts'] as $contactType => $contactID) {
                $contactsXml .= '<domain:contact type="' . $contactType . '">' . $contactID . '</domain:contact>' . "\n";
            }
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);

        $from[] = '/{{ period }}/';
        $to[] = is_numeric($params['period']) ? $params['period'] : 1;

        $from[] = '/{{ hostObjs }}/';
        $to[] = $nsXML;

        $from[] = '/{{ registrant }}/';
        $to[] = htmlspecialchars($params['registrant']);

        $from[] = '/{{ contacts }}/';
        $to[] = $contactsXml;


        $from[] = '/{{ authInfoPw }}/';
        $to[] = htmlspecialchars($params['authInfoPw']);

        $from[] = '/{{ noticeID }}/';
        $to[] = htmlspecialchars($params['noticeID']);
        $from[] = '/{{ notAfter }}/';
        $to[] = htmlspecialchars($params['notAfter']);
        $from[] = '/{{ acceptedDate }}/';
        $to[] = htmlspecialchars($params['acceptedDate']);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-createClaims-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
    <create>
      <domain:create
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">{{ period }}</domain:period>
        <domain:ns>
          {{ hostObjs }}
        </domain:ns>
        <domain:registrant>{{ registrant }}</domain:registrant>
        {{ contacts }}
        <domain:authInfo>
          <domain:pw>{{ authInfoPw }}</domain:pw>
        </domain:authInfo>
      </domain:create>
      <extension>
         <launch:create xmlns:launch="urn:ietf:params:xml:ns:launch-1.0">
            <launch:phase>claims</launch:phase>
            <launch:notice>
               <launch:noticeID>{{ noticeID }}</launch:noticeID>
               <launch:notAfter>{{ notAfter }}</launch:notAfter>
               <launch:acceptedDate>{{ acceptedDate }}</launch:acceptedDate>
            </launch:notice>
         </launch:create>
      </extension>
    </create>
    <clTRID>{{ clTRID }}</clTRID>
  </command>');

        return $r = $this->_write($xml, __FUNCTION__);
    }

    public function domainCreateDNSSEC($domainName, $params)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domainName);
        $from[] = '/{{ period }}/';
        $to[] = (int)($params['period']);
        if (isset($params['nss'])) {
            $text = '';
            foreach ($params['nss'] as $hostObj) {
                $text .= '<domain:hostObj>' . $hostObj . '</domain:hostObj>' . "\n";
            }
            $from[] = '/{{ hostObjs }}/';
            $to[] = $text;
        } else {
            $from[] = '/{{ hostObjs }}/';
            $to[] = '';
        }
        $from[] = '/{{ registrant }}/';
        $to[] = htmlspecialchars($params['registrant']);
        $text = '';
        foreach ($params['contacts'] as $contactType => $contactID) {
            $text .= '<domain:contact type="' . $contactType . '">' . $contactID . '</domain:contact>' . "\n";
        }
        $from[] = '/{{ contacts }}/';
        $to[] = $text;
        $from[] = '/{{ authInfoPw }}/';
        $to[] = htmlspecialchars($params['authInfoPw']);
        if ($params['dnssec_records'] == 1) {
            $from[] = '/{{ dnssec_data }}/';
            $to[] = "<secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_1']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_1']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_1']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_1']) . "</secDNS:digest>
		  </secDNS:dsData>";
        } elseif ($params['dnssec_records'] == 2) {
            $from[] = '/{{ dnssec_data }}/';
            $to[] = "<secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_1']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_1']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_1']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_1']) . "</secDNS:digest>
		  </secDNS:dsData>
		  <secDNS:dsData>
			<secDNS:keyTag>" . htmlspecialchars($params['keyTag_2']) . "</secDNS:keyTag>
			<secDNS:alg>" . htmlspecialchars($params['alg_2']) . "</secDNS:alg>
			<secDNS:digestType>" . htmlspecialchars($params['digestType_2']) . "</secDNS:digestType>
			<secDNS:digest>" . htmlspecialchars($params['digest_2']) . "</secDNS:digest>
		  </secDNS:dsData>";
        }
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-domain-createDNSSEC-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
    <create>
      <domain:create
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">{{ period }}</domain:period>
        <domain:ns>
          {{ hostObjs }}
        </domain:ns>
        <domain:registrant>{{ registrant }}</domain:registrant>
        {{ contacts }}
        <domain:authInfo>
          <domain:pw>{{ authInfoPw }}</domain:pw>
        </domain:authInfo>
      </domain:create>
	<extension>
	  <secDNS:create xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
		<secDNS:add>
		  {{ dnssec_data }}
		</secDNS:add>
	  </secDNS:create>
	</extension>
    </create>
    <clTRID>{{ clTRID }}</clTRID>
  </command>');

        return $r = $this->_write($xml, __FUNCTION__);
    }

    //contact-chg
    //contact-update

    // $contacts -> MUST TRY strtoupper
    public function contactCheck($contactIdentifier)
    {
        $from = $to = [];
        $from[] = '/{{ id }}/';
        $to[] = ok_epp_simple_ArrStrTag($contactIdentifier, "contact:id", "strtoupper");
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-contact-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <check>
            <contact:check
                xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"
                xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
                {{ id }}
            </contact:check>
        </check>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $result = [];
        foreach (ok_epp_arr2arr($r['resData']['contact:chkData']['contact:cd']) as $dList) {
            $result[] = [
                "id" => $dList['contact:id'],
                "avail" => $dList['contact:id_attr']['avail'],
                "reason" => isset($dList['contact:reason']) ? $dList['contact:reason'] : "",
            ];
        }
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "contact" => $result

        ];
        return $return;
    }

    public function contactInfo($contactIdentifier)
    {
        if (!is_string($contactIdentifier)) {
            throw new exception('Invalid Contact Type.');
        }

        $from = $to = [];
        $from[] = '/{{ id }}/';
        $to[] = htmlspecialchars($contactIdentifier);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-contact-info-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <info>
            <contact:info xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>{{ id }}</contact:id>
            </contact:info>
        </info>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['contact:infData'];

        if (empty($dList['contact:status'])) {
            $dStatus = [$dList['contact:status_attr']['s']];
        } else {
            $dStatus = [];
            foreach ($dList['contact:status'] as $dStatusc) {
                if (isset($dStatusc['s'])) {
                    $dStatus[] = $dStatusc['s'];
                }
            }
        }

        $addr = $dList['contact:postalInfo']['contact:addr'];
        $result = [
            "id" => $dList['contact:id'],
            "roid" => $dList['contact:roid'],
            "status" => $dStatus,
            "postalInfo" => [
                "name" => $dList['contact:postalInfo']['contact:name'],
                "org" => ($dList['contact:postalInfo']['contact:org'] ?? ''),
                "addr" => [
                    "street" => $addr['contact:street'],
                    "city" => $addr['contact:city'],
                    "state" => $addr['contact:sp'],
                    "postal" => $addr['contact:pc'],
                    "country" => $addr['contact:cc'],
                ],
                "type" => $dList['contact:postalInfo_attr']['type']
            ],

            "voice" => isset($dList['contact:voice']) ? $dList['contact:voice'] : "",
            "fax" => isset($dList['contact:fax']) ? $dList['contact:fax'] : "",
            "email" => $dList['contact:email'],
            "clID" => $dList['contact:clID'],
            "crID" => $dList['contact:crID'],

            "upID" => isset($dList['contact:upID']) ? $dList['contact:upID'] : "",
            "upDate" => isset($dList['contact:upDate']) ? $dList['contact:upDate'] : "",
            "crDate" => $dList['contact:crDate'],

            "authInfo" => $dList['contact:authInfo']['contact:pw'],
        ];

        if (isset($addr['contact:street'])) {
            $streetCount = 1;
            if (is_array($addr['contact:street'])) {
                foreach ($addr['contact:street'] as $svalue) {
                    $result['postalInfo']['addr']['street' . $streetCount] = $svalue;
                    $streetCount++;
                }
            } else {
                $result['postalInfo']['addr']['street' . $streetCount] = $addr['contact:street'];
            }
        }

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "contact" => $result

        ];
        return $return;
    }

    public function domainContactInfo($domainName, $phoneDotRemove = false)
    {
        if (!is_string($domainName)) {
            throw new exception('Invalid Domain Type.');
        }

        $dInfo = $this->domainInfo($domainName);

        $contents = [];
        $contents['registrant'] = $dInfo['domain']['registrant'];
        foreach ($dInfo['domain']['contact'] as $dKey => $dValue) {
            $contents[$dKey] = $dValue;
        }

        //get contact data
        $ucIds = array_unique(array_values($contents));
        $cidData = [];
        foreach ($ucIds as $civalue) {
            $contDt = $this->contactInfo($civalue);

            $phoneNumber = ($contDt['contact']['voice'] ?? '');

            $cf = [];
            $cf["Full Name"] = $contDt['contact']['postalInfo']['name'];
            $cf["Email"] = $contDt['contact']['email'];

            $cf["Company Name"] = ($contDt['contact']['postalInfo']['org'] ?? '');


            $cf["Address 1"] = ($contDt['contact']['postalInfo']['addr']['street1'] ?? '');
            $cf["Address 2"] = ($contDt['contact']['postalInfo']['addr']['street2'] ?? '');

            if (!empty($contDt['contact']['postalInfo']['addr']['street3'])) {
                $cf["Address 3"] = $contDt['contact']['postalInfo']['addr']['street3'];
            }

            $cf["City"] = $contDt['contact']['postalInfo']['addr']['city'];
            $cf["State"] = $contDt['contact']['postalInfo']['addr']['state'];
            $cf["Postcode"] = $contDt['contact']['postalInfo']['addr']['postal'];
            $cf["Country"] = $contDt['contact']['postalInfo']['addr']['country'];

            $cf["Phone Number"] = $phoneDotRemove === true ? str_replace(".", "", $phoneNumber) : $phoneNumber;
            $cidData[$civalue] = $cf;
        }

        $cccData = [];
        foreach ($contents as $ccType => $ccId) {
            $cccData[ucfirst($ccType)] = $cidData[$ccId];
        }

        return ["contents" => $cccData, "cId" => $contents, "unqId" => $ucIds];
    }

    //Contact Create
    public function contactCreate($contactIdentifier, $params)
    {
        if (!is_string($contactIdentifier) || !is_array(($params))) {
            throw new exception('Invalid Contact Type.');
        }

        $this->setParams($params);

        $from = $to = [];
        $from[] = '/{{ type }}/';
        $to[] = (isset($params['postalInfo_type']) ? htmlspecialchars($params['postalInfo_type']) : "int");
        $from[] = '/{{ id }}/';
        $to[] = strtoupper($contactIdentifier);
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($this->getParams('firstname') . ' ' . ($params['lastname'] ?? ''));
        $from[] = '/{{ org }}/';
        $to[] = htmlspecialchars($this->getParams('companyname'));
        $from[] = '/{{ street1 }}/';
        $to[] = htmlspecialchars($this->getParams('address1'));
        $from[] = '/{{ street2 }}/';
        $to[] = (isset($params['address2']) ? htmlspecialchars($this->getParams('address2')) : '');
        $from[] = '/{{ street3 }}/';
        $street3 = (isset($params['address3']) ? htmlspecialchars($this->getParams('address3')) : '');
        $to[] = htmlspecialchars($street3);
        $from[] = '/{{ city }}/';
        $to[] = htmlspecialchars($this->getParams('city'));
        $from[] = '/{{ state }}/';
        $to[] = htmlspecialchars($this->getParams('state'));
        $from[] = '/{{ postcode }}/';
        $to[] = htmlspecialchars($this->getParams('postcode'));
        $from[] = '/{{ country }}/';
        $to[] = htmlspecialchars($this->getParams('country'));
        $from[] = '/{{ phonenumber }}/';
        $to[] = htmlspecialchars($this->getParams('fullphonenumber'));
        $from[] = '/{{ fax }}/';
        $to[] = (isset($params['fax']) ? htmlspecialchars($this->getParams('fax')) : "");
        $from[] = '/{{ email }}/';
        $to[] = htmlspecialchars($this->getParams('email'));
        $from[] = '/{{ authInfo }}/';
        $to[] = htmlspecialchars(ok_epp_generateObjectPW());
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-contact-create-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
        <create>
            <contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
                <contact:id>{{ id }}</contact:id>
                <contact:postalInfo type="{{ type }}">
                    <contact:name>{{ name }}</contact:name>
                    <contact:org>{{ org }}</contact:org>
                    <contact:addr>
                        <contact:street>{{ street1 }}</contact:street>
                        <contact:street>{{ street2 }}</contact:street>
                        <contact:street>{{ street3 }}</contact:street>
                        <contact:city>{{ city }}</contact:city>
                        <contact:sp>{{ state }}</contact:sp>
                        <contact:pc>{{ postcode }}</contact:pc>
                        <contact:cc>{{ country }}</contact:cc>
                    </contact:addr>
                </contact:postalInfo>
                <contact:voice>{{ phonenumber }}</contact:voice>
                <contact:fax>{{ fax }}</contact:fax>
                <contact:email>{{ email }}</contact:email>
                <contact:authInfo>
                    <contact:pw>{{ authInfo }}</contact:pw>
                </contact:authInfo>
            </contact:create>
        </create>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['contact:creData'];
        $result = [
            "success" => true,
            "id" => $dList['contact:id'],
            "crDate" => $dList['contact:crDate'],
        ];

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "contact" => $result

        ];
        return $return;
    }

    public function contactDelete($contactIdentifier)
    {
        if (!is_string($contactIdentifier)) {
            throw new exception('Invalid contact type');
        }

        $from = $to = [];
        $from[] = '/{{ id }}/';
        $to[] = htmlspecialchars($contactIdentifier);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-contact-delete-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
    <delete>
        <contact:delete
            xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
            <contact:id>{{ id }}</contact:id>
        </contact:delete>
    </delete>
    <clTRID>{{ clTRID }}</clTRID>
</command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "contact" => [
                "success" => true,
                "id" => $contactIdentifier,
                "msg" => "Contact Deleted"
            ]

        ];
        return $return;
    }

    //contact Update and chg
    public function contactUpdate($contactIdentifier, $params)
    {
        if (!is_string($contactIdentifier)) {
            throw new exception('Invalid contact type');
        }

        if (!isset($params['type'])) {
            $params['type'] = 'int';
        }

        $this->setParams($params);

        $from = $to = [];
        $from[] = '/{{ type }}/';
        $to[] = htmlspecialchars($this->getParams('type'));
        $from[] = '/{{ id }}/';
        $to[] = htmlspecialchars($contactIdentifier);
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($this->getParams('firstname') . ' ' . ($params['lastname'] ?? ''));
        $from[] = '/{{ org }}/';
        $to[] = htmlspecialchars($this->getParams('companyname'));
        $from[] = '/{{ street1 }}/';
        $to[] = htmlspecialchars($this->getParams('address1'));
        $from[] = '/{{ street2 }}/';
        $to[] = (isset($params['address2']) ? htmlspecialchars($this->getParams('address2')) : '');
        $from[] = '/{{ street3 }}/';
        $street3 = (!empty($params['address3']) ? htmlspecialchars($this->getParams('address3')) : '');
        $to[] = htmlspecialchars($street3);
        $from[] = '/{{ city }}/';
        $to[] = htmlspecialchars($this->getParams('city'));
        $from[] = '/{{ state }}/';
        $to[] = htmlspecialchars($this->getParams('state'));
        $from[] = '/{{ postcode }}/';
        $to[] = htmlspecialchars($this->getParams('postcode'));
        $from[] = '/{{ country }}/';
        $to[] = htmlspecialchars($this->getParams('country'));
        $from[] = '/{{ voice }}/';
        $to[] = htmlspecialchars($this->getParams('fullphonenumber'));
        $from[] = '/{{ fax }}/';
        $to[] = (isset($params['fax']) && preg_match('/^(\+[0-9]{1,3}\.[0-9]{1,14})?$/', $params['fax']) ? htmlspecialchars($this->getParams('fax')) : '');
        $from[] = '/{{ email }}/';
        $to[] = htmlspecialchars($this->getParams('email'));
        $from[] = '/{{ clTRID }}/';

        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-contact-update-' . $clTRID);

        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';
        $xml = preg_replace($from, $to, '<command>
	<update>
	  <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
		<contact:id>{{ id }}</contact:id>
		<contact:chg>
		  <contact:postalInfo type="{{ type }}">
			<contact:name>{{ name }}</contact:name>
			<contact:org>{{ org }}</contact:org>
			<contact:addr>
			  <contact:street>{{ street1 }}</contact:street>
			  <contact:street>{{ street2 }}</contact:street>
			  <contact:street>{{ street3 }}</contact:street>
			  <contact:city>{{ city }}</contact:city>
			  <contact:sp>{{ state }}</contact:sp>
			  <contact:pc>{{ postcode }}</contact:pc>
			  <contact:cc>{{ country }}</contact:cc>
			</contact:addr>
		  </contact:postalInfo>
		  <contact:voice>{{ voice }}</contact:voice>
		  <contact:fax>{{ fax }}</contact:fax>
		  <contact:email>{{ email }}</contact:email>
		</contact:chg>
	  </contact:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "contact" => [
                "success" => true,
                "id" => $contactIdentifier,
                "msg" => "Contact Updated"
            ]

        ];
        return $return;
    }

    /**
     * @param string $contactIdentifier
     * @param int $protectenable 1 or 0
     *
     * @return array
     */
    public function contactUpdateProtect($contactIdentifier, $protectenable = 1)
    {
        if (!is_string($contactIdentifier)) {
            throw new exception('Invalid Contact Type.');
        }

        $from = $to = [];
        $from[] = '/{{ id }}/';
        $to[] = htmlspecialchars($contactIdentifier);

        $from[] = '/{{ flag }}/';
        $to[] = ($protectenable ? 1 : 0);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-contact-updateProtect-' . $clTRID);

        $xml = preg_replace($from, $to, '<command>
	<update>
	  <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
		<contact:id>{{ id }}</contact:id>
		<contact:chg>
          <contact:disclose flag="{{ flag }}">
			<contact:name type="int"/>
			<contact:addr type="int"/>
			<contact:voice/>
			<contact:fax/>
			<contact:email/>
          </contact:disclose>
		</contact:chg>
	  </contact:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "contact" => [
                "success" => true,
                "id" => $contactIdentifier,
                "msg" => "Contact Updated"
            ]

        ];
        return $return;
    }

    public function hostCheck($hostNames)
    {
        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = ok_epp_simple_ArrStrTag($hostNames, "host:name");
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-host-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
    <check>
        <host:check
            xmlns:host="urn:ietf:params:xml:ns:host-1.0"
            xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
            {{ name }}
        </host:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
</command>');

        $r = $this->_write($xml, __FUNCTION__);
        $result = [];
        foreach (ok_epp_arr2arr($r['resData']['host:chkData']['host:cd']) as $dList) {
            $result[] = [
                "name" => $dList['host:name'],
                "avail" => $dList['host:name_attr']['avail'],
                "reason" => isset($dList['host:reason']) ? $dList['host:reason'] : "",
            ];
        }
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "host" => $result

        ];
        return $return;
    }

    public function hostInfo($hostName)
    {
        if (!is_string($hostName)) {
            throw new exception('Invalid Host type');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = $hostName;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-host-info-' . $clTRID);

        $xml = preg_replace($from, $to, '<command>
        <info>
            <host:info
                xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>{{ name }}</host:name>
            </host:info>
        </info>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['host:infData'];

        if (empty($dList['host:status'])) {
            $dStatus = [$dList['host:status_attr']['s']];
        } else {
            $dStatus = [];
            foreach ($dList['host:status'] as $dStatusc) {
                if (isset($dStatusc['s'])) {
                    $dStatus[] = $dStatusc['s'];
                }
            }
        }

        $addr = [];
        if (isset($dList['host:addr'])) {
            if (isset($dList['host:addr_attr'])) {
                $addr[] = $dList['host:addr'];
            } else {
                foreach ($dList['host:addr'] as $ipd) {
                    if (is_string($ipd)) {
                        $addr[] = $ipd;
                    }
                }
            }
        }

        $result = [
            "name" => $dList['host:name'],
            "roid" => $dList['host:roid'],
            "status" => $dStatus,
            'addr' => $addr,
            "clID" => $dList['host:clID'],
            "crID" => $dList['host:crID'],
            "crDate" => $dList['host:crDate'],
            "upID" => isset($dList['host:upID']) ? $dList['host:upID'] : "",
            "upDate" => isset($dList['host:upDate']) ? $dList['host:upDate'] : "",
        ];

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "host" => $result

        ];
        return $return;
    }

    // $ips -> when we create "Private nameserver" and it's only for same registrar registered domain
    public function hostCreate($hostName, $ips = null)
    {
        if (!is_string($hostName)) {
            throw new exception('Invalid Host type');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($hostName);
        $from[] = '/{{ ip }}/';
        $to[] = ok_epp_simple_IpsArrStrTag($ips, "host:addr");

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-host-create-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
	<create>
	  <host:create
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
		{{ ip }}
	  </host:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>');

        $r = $this->_write($xml, __FUNCTION__);

        $dList = $r['resData']['host:creData'];
        $result = [
            "success" => true,
            "name" => $dList['host:name'],
            "crDate" => $dList['host:crDate'],
        ];

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "host" => $result

        ];
        return $return;
    }

    public function hostDelete($hostName)
    {
        if (!is_string($hostName)) {
            throw new exception('Invalid Host type');
        }

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($hostName);
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-host-delete-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <delete>
            <host:delete
                xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>{{ name }}</host:name>
            </host:delete>
        </delete>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "host" => [
                "success" => true,
                "name" => $hostName,
                "msg" => "Host Deleted"
            ]

        ];
        return $return;
    }

    public function hostUpdate($hostName, $addIps = null, $remIps = null)
    {
        if (!is_string($hostName)) {
            throw new exception('Invalid Host type');
        }

        $addIpsXML = ok_epp_simple_IpsArrStrTag($addIps, "host:addr");
        $remIpsXML = ok_epp_simple_IpsArrStrTag($remIps, "host:addr");

        $from = $to = [];
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($hostName);

        $from[] = '/{{ addIp }}/';
        $to[] = !empty($addIpsXML) ? '<host:add>' . $addIpsXML . '</host:add>' : "";

        $from[] = '/{{ remIp }}/';
        $to[] = !empty($remIpsXML) ? '<host:rem>' . $remIpsXML . '</host:rem>' : "";

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-host-update-' . $clTRID);
        $xml = preg_replace($from, $to, '<command>
        <update>
            <host:update
                xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                <host:name>{{ name }}</host:name>
                {{ addIp }}
                {{ remIp }}
            </host:update>
        </update>
        <clTRID>{{ clTRID }}</clTRID>
    </command>');

        $r = $this->_write($xml, __FUNCTION__);
        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "host" => [
                "success" => true,
                "name" => $hostName,
                "msg" => "Host Updated"
            ]

        ];
        return $return;
    }

    public function pollReq()
    {
        $from = $to = [];
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-poll-req-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';
        $xml = preg_replace($from, $to, '<command>
       <poll op="req"/>
       <clTRID>{{ clTRID }}</clTRID>
     </command>');
        $r = $this->_write($xml, __FUNCTION__);

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],
            "poll" => [
                "qDate" => ($r['msgQ']['qDate'] ?? ""),
                "msg" => ($r['msgQ']['msg'] ?? ""),
                "msg_last_id" => ($r['msgQ_attr']['id'] ?? ""),
                "msg_count" => ($r['msgQ_attr']['count'] ?? "")
            ]
        ];
        return $return;
    }

    public function pollAck($msgID)
    {
        $from = $to = [];
        $from[] = '/{{ message }}/';
        $to[] = htmlspecialchars($msgID);

        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->getConfig("identityprefix") . '-poll-ack-' . $clTRID);
        $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
        $to[] = '';

        $xml = preg_replace($from, $to, '<command>
       <poll op="ack" msgID="{{ message }}"/>
       <clTRID>{{ clTRID }}</clTRID>
     </command>');

        return $r = $this->_write($xml, __FUNCTION__);

        $return = [
            "code" => $r['result_attr']['code'],
            "msg" => $r['result']['msg'],
            "lang" => $r['result']['msg_attr']['lang'],


        ];
        return $return;
    }


    //class end
}
