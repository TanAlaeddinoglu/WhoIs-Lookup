<?php
include "whois.php";
$whois = new Whois();
$domain = '';
function domainSeperator($domain)
{
    $domain = strip_tags($domain);
    $uzanti = strrchr($domain, '.');
    $parsedExt = substr($uzanti, 1);
    return $parsedExt;
}

function  whoIsServerConn($domain)
{

        global $whois; // Access $whois object defined outside the function

        // Check if domain is provided
        if (!empty($domain)) {
            $domain = strip_tags($domain);
            $uzanti = strrchr($domain, '.');
            $parsedExt = substr($uzanti, 1);
            if (isset($whois->whoisServers[$parsedExt])) {
                $whois_server = $whois->whoisServers[$parsedExt];
                $fp = fsockopen($whois_server, 43);
                if (!$fp) {
                    die("Hata oluştu: Unable to connect to WHOIS server");
                }
                fwrite($fp, $domain . "\r\n");
                $response = '';
                while (!feof($fp)) {
                    $response .= fgets($fp, 128);
                }
                fclose($fp);
                return $response;
            } else {
                return "Belirtilen uzantı için WHOIS sunucusu bulunamadı.";
            }
        } else {
            return "Domain bilgisi bulunamadı.";
        }
    }

function parseDomainInfo($response): array
{
    $domainKeywords = [
        [ 'Domain Name' => ['Domain Name','domain name','Domain name','Domain','DOMAIN NAME','domain']],
        [ 'Domain ID'=> ['Domain ID', 'Domain Name ID', 'Registry Domain ID', 'ROID'] ],
        [ 'Updated Date'=> ['Last updated on','last-update','Last Update Time', 'Updated Date', 'Domain Last Updated Date', 'last modified','Domain record last updated','Last updated'] ],
        [ 'Created Date'=> ['Creation Date', 'Created On', 'Created on..............','Registration Time', 'Domain Create Date', 'Domain Registration Date', 'Domain Name Commencement Date', 'created','Domain record activated','Registered on'] ],
        [ 'Expiry Date'	=> ['Expiry Date', 'Expiration Date', 'Expires on..............', 'Expiration Time', 'Domain Expiration Date', 'Registrar Registration Expiration Date', 'Record expires on', 'Registry Expiry Date', 'renewal date','Domain expires','paid-till'] ],

    ];

    $parsedDomain = [];
    $parsedInfoArr = [];
    $replacedResponse = str_replace("*", " ", $response);
    $trimmedResponse = trim($replacedResponse);
    $lines = explode("\n", $trimmedResponse);
{
    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) == 2) {
            $key = trim($parts  [0]);
            $value = trim($parts[1]);
            if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' &&
                $key !== '>>> Last update of whois database'&& $key !== 'Hidden upon user request' && $value != null)
                $parsedInfoArr[$key] = $value;
                foreach ($parsedInfoArr as $parsedInfoKey => $parsedInfoValue) {
                    foreach ($domainKeywords as $domainKeyword) {
                        foreach ($domainKeyword as $var => $keywords) {
                            foreach ($keywords as $keyword) {
                                if (strcasecmp($keyword, $parsedInfoKey) === 0) {
                                    $parsedDomain[$var] = $parsedInfoValue;
                                }
                            }
                        }
                    }
                }
           }
        }

    }

    return $parsedDomain;
}

function parseRegistrarInfo($response): array
{
    $registrarKeywords = [
    [ 'WHOIS Server'=> ['Whois Server', 'WHOIS SERVER', 'Registrar WHOIS Server','admin-contact'] ],
    [ 'Registrar URL'=> ['Registrar URL', 'Registrar URL (registration services)','URL'] ],
    [ 'Registrar' => ['Registrar', 'registrar', 'Registrant', 'Registrar Name', 'Created by Registrar', 'Organization Name'] ],
    [ 'IANA'=> ['Registrar IANA ID', 'IANA ID'] ],
    [ 'NIC Handle'=> ['NIC Handle'] ],
    [ 'Abuse Mail'=> ['Registrar Abuse Contact Email'] ],
    [ 'Abuse Phone'=> ['Registrar Abuse Contact Phone', 'Phone'] ],

];
    $parsedRegistrar = [];
    $replacedResponse = str_replace("*", " ", $response);
    $trimmedResponse = trim($replacedResponse);
    $lines = explode("\n", $trimmedResponse);

    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) == 2) {
            $key = trim($parts  [0]);
            $value = trim($parts[1]);
            if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' &&
                $key !== '>>> Last update of whois database'&& $key !== 'Hidden upon user request' && $value != null)         {
                $parsedInfoArr[$key] = $value;
                foreach ($parsedInfoArr as $parsedInfoKey => $parsedInfoValue) {
                    foreach ($registrarKeywords as $registrarKeyword) {
                        foreach ($registrarKeyword as $var => $keywords) {
                            foreach ($keywords as $keyword) {
                                if (strcasecmp($keyword, $parsedInfoKey) === 0) {
                                    $parsedRegistrar[$var] = $parsedInfoValue;
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    return $parsedRegistrar;

}

function parseOtherInfo($response): array
{
    $otherKeywords = [
        [ 'DNS Secure' => ['DNSSEC']],
        [ 'Registrant'=> ['Registrant','registrant','org'] ],
        [ 'Provider' => ['Reseller', 'Registration Service Provider'] ],
    ];
    $parsedOtherInfo = [];
    $replacedResponse = str_replace("*", " ", $response);
    $trimmedResponse = trim($replacedResponse);
    $lines = explode("\n", $trimmedResponse);

    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) == 2) {
            $key = trim($parts  [0]);
            $value = trim($parts[1]);
            if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' &&
                $key !== '>>> Last update of whois database'&& $key !== 'Hidden upon user request' && $value != null) {
                $parsedInfoArr[$key] = $value;
                foreach ($parsedInfoArr as $parsedInfoKey => $parsedInfoValue) {
                    foreach ($otherKeywords as $otherKeyword) {
                        foreach ($otherKeyword as $var => $keywords) {
                            foreach ($keywords as $keyword) {
                                if (strcasecmp($keyword, $parsedInfoKey) === 0) {
                                    $parsedOtherInfo[$var] = $parsedInfoValue;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return $parsedOtherInfo;

}

function parseTheNameserver ($response,$extension): array
{
    $replacedResponse = str_replace("*", " ", $response);
    $trimmedResponse = trim($replacedResponse);
    $lines = explode("\n", $trimmedResponse);
    $nameservers = array();
    if ($extension=="tr" || $extension=="nl")
    {
        $pattern = '/(?:Name Servers|Domain Servers|Domain nameservers|Name servers):(.*?)(?:Creation Date|Domain record activated|Additional Info|\z)/s';
        preg_match($pattern, $trimmedResponse, $matches);
        // Check if matches were found
        if (isset($matches[1])) {
            // Extract the DNS server names from the matched substring
            $serverInfo = trim($matches[1]);

            // Explode the string by space and merge the resulting array into $nameservers
            $nameservers = array_merge($nameservers, preg_split('/\s+/', $serverInfo));
            $nameservers = removeIPNumbers($nameservers);
        }
        return $nameservers;
    }
    else
    {
        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);

            if (count($parts) == 2) {
                $key = trim($parts  [0]);
                $value = trim($parts[1]);
                if ($key === 'Name Server' || $key === 'Domain Servers' || $key === 'Domain nameservers' || $key === 'nserver' ) {
                    $nameservers[] = $value;
                }
            }

        }

    }

    return $nameservers;

}

function parseStatusCodes($response,$extension): array
{
    $statusCodeKeywords = [
        ['Add Period' => ['addPeriod']],
        ['Auto Renew Period' => ['autoRenewPeriod']],
        ['Inactive' => ['inactive']],
        ['Active' => ['ok', 'Active', 'active',' active ']],
        ['Pending Create' => ['pendingCreate']],
        ['Pending Delete' => ['pendingDelete']],
        ['Pending Renew' => ['pendingRenew']],
        ['Pending Restore' => ['pendingRestore']],
        ['Pending Transfer' => ['pendingTransfer']],
        ['Pending Update' => ['pendingUpdate']],
        ['Redemption Period' => ['redemptionPeriod']],
        ['Renew Period' => ['renewPeriod']],
        ['Server Delete Prohibited' => ['serverDeleteProhibited']],
        ['Server Hold' => ['serverHold']],
        ['Server Renew Prohibited' => ['serverRenewProhibited']],
        ['Server Transfer Prohibited' => ['serverTransferProhibited', 'The domain is LOCKED to transfer.']],
        ['Server Update Prohibited' => ['serverUpdateProhibited']],
        ['Client Delete Prohibited' => ['clientDeleteProhibited']],
        ['Client Hold' => ['clientHold',]],
        ['Client Renew Prohibited' => ['clientRenewProhibited']],
        ['Client Transfer Prohibited' => ['clientTransferProhibited', 'The domain is LOCKED to transfer.']],
        ['Client Update Prohibited' => ['clientUpdateProhibited']]

    ];

    $classifiedStatuses = [];
    $statusCodes = [];
    //$pattern = '/Domain Status: (.*?)[\s\n]|Frozen Status: (.*?)[\s\n]|Transfer Status: (.*?)[\s\n]|Status: (.*?)[\s\n]/';
    $replacedResponse = str_replace("*", " ", $response);
    $trimmedResponse = trim($replacedResponse);
        $patternNL = '/Status: (.*?)\s*Registrar:/s';
        $patternTR = '/Domain Status: (.*?)\s*Frozen Status: (.*?)\s*Transfer Status: (.*?)\s*Registrant:/s';
        $pattern = '/(?:Domain Status|Frozen Status|Transfer Status|Status|state): (.*?)[\s\n]/';

    if ($extension=='tr'){
        preg_match_all($patternTR,$trimmedResponse,$matchesTR);
       for ($i = 1; $i < count($matchesTR); $i++) {
            foreach ($matchesTR[$i] as $match) {
                $statusCodes[] = $match;
            }
        }

        foreach ($statusCodes as $statusCode){
            foreach ($statusCodeKeywords as $keyword) {
                foreach ($keyword as $category => $codes) {
                    if (in_array($statusCode, $codes)) {
                        // Found a matching category for the status code
                        $classifiedStatuses[] = ['status' => $statusCode, 'category' => $category];
                    }
                }
            }
        }
    }
    elseif ($extension == 'nl') {
        preg_match($patternNL, $trimmedResponse, $matches);

        // Check if matches are found
        if (count($matches) > 1) {
            $statusCode = trim($matches[1]);

            // Classify NL status code
            foreach ($statusCodeKeywords as $keyword) {
                foreach ($keyword as $category => $codes) {
                    if (in_array($statusCode, $codes)) {
                        // Found a matching category for the status code
                        $classifiedStatuses[] = ['status' => $statusCode, 'category' => $category];
                    }
                }
            }
        }
    }
    else{
        preg_match_all($pattern, $trimmedResponse, $matches);

        if (isset($matches[1])) {
            $statusCodes = $matches[1];
        }

        foreach ($statusCodes as $statusCode){
            foreach ($statusCodeKeywords as $keyword) {
                foreach ($keyword as $category => $codes) {
                    if (in_array($statusCode, $codes)) {
                        // Found a matching category for the status code
                        $classifiedStatuses[] = ['status' => $statusCode, 'category' => $category];
                    }
                }
            }
        }
    }

    return $classifiedStatuses;
}


function displayInfo(array $domainArray, array $registrarArray, array $otherInfoArray, array $nameservers, array $statusCodes ): void
{
    if (empty($domainArray)) {
        echo "<br>"."!!!No domain found."."<br>";
    }
    else {
        echo '<br>'."DOMAIN INFO:"."<br>";
        foreach ($domainArray as $index => $domainInfo) {
            echo $index.':'."$domainInfo".'<br>';
        }
    }
    if (empty($registrarArray)) {
        echo "<br>"."!!!No Registrar Info Found."."<br>";
    }
    else {
        echo '<br>'."CONTACT INFO:"."<br>";
        foreach ($registrarArray as $index => $registrarInfo) {
            echo $index.':'."$registrarInfo".'<br>';
        }
    }
    if (!empty($otherInfoArray)) {
        echo '<br>'."OTHER INFO:"."<br>";
        foreach ($otherInfoArray as $index => $otherInfo) {
            echo $index.':'."$otherInfo".'<br>';
        }
    }
    if (empty($nameservers)) {
        echo "<br>"."!!!No nameservers found."."<br>";
        return;
    }
    else {
        echo '<br>'."Nameservers:"."<br>";
        foreach ($nameservers as $index => $nameserver) {
            echo "$nameserver".'<br>';
        }
    }
    if (empty($statusCodes)) {
        echo "<br>"."!!!No status found."."<br>";
        return;
    }
    else {
        echo '<br>'."Status:"."<br>";
        foreach ($statusCodes as $statusCode) {
            echo $statusCode['category'] . '<br>';
        }
    }
}
function removeIPNumbers($array): array
{
    //Name serverlarla gelen IPv4 numaralarını silmek için fonskiyon
    $pattern = '/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\b/';
    //$pattern = '/\b(?:\d{1,3}\.){3}\d{1,3}\b/';
    // Filter the array to remove elements that match the pattern
    return array_filter($array, function($item) use ($pattern) {
        return !preg_match($pattern, $item);
    }
    );
}


function parseTheTRData ($response): array
{
   //com.tr gibi standart olmayan uzantilari parse eder

    $replacedResponse = str_replace("*", " ", $response);
    $trimmedResponse = trim($replacedResponse);
    $lines = explode("\n", $trimmedResponse);
    $parsedInfoArr = array();


    foreach ($lines as $line) {
        // Split the line by ':' character to extract key-value pairs
        $parts = explode(':', $line, 2);
        //var_dump($parsedInfo);
        // Check if the line contains the ':' character and has exactly two parts
        if (count($parts) == 2) {
            $key = trim($parts  [0]);
            $value = trim($parts[1]);
            if ($key !== 'Domain Servers' && $key !== 'Status' && $key !== 'TERMS OF USE' && $key !== 'Terms of Use' && $key !== 'NOTICE' &&
                $key !== 'For more information on Whois status codes, please visit https' && $key !== 'by the following terms of use' &&
                $key !== 'to' && $key !== 'Domain Status' && $key !== 'Name Server' && $key !== 'URL of the ICANN Whois Inaccuracy Complaint Form' && $key !== '>>> Last update of whois database') {
                $parsedInfoArr[$key] = $value;
            }
        }

    }
    return $parsedInfoArr;
}
function displayStatusCodes(array $statusCodes) {
    if (empty($statusCodes)) {
        echo "No status found."."<br>";
        return;
    }
    else {
        echo '<br>'."Status:"."<br>";
        foreach ($statusCodes as $statusCode) {
            echo $statusCode['category'] . '<br>';
        }
    }
}
function displayParsedData($parsedInfo) {
    $domainName = "";
    $contactInfo = "";
    $otherInfo = "";

    foreach ($parsedInfo as $key => $value) {
        // Check if the key belongs to domain name
        if (strpos($key, 'Domain Name') !== false
            ||strpos($key, 'Domain') !== false
            ||strpos($key, 'Registry Domain ID') !== false
            || strpos($key, 'Date') !== false
            || strpos($key, 'Created on') !== false
            || strpos($key, 'Expires on') !== false
            || strpos($key, 'Last Update Time') !== false) {
            $domainName .= $key.": $value".'<br>';
        }
        // Check if the key belongs to contact info
        elseif (strpos($key, 'Registrant') !== false
            || strpos($key, 'Registrar') !== false
            || strpos($key, 'Address') !== false
            || strpos($key, 'Phone') !== false
            || strpos($key, 'Fax') !== false
            || strpos($key, 'Email') !== false
            || strpos($key, 'Admin') !== false
            || strpos($key, 'Tech') !== false
            || strpos($key, 'NIC Handle') !== false
            || strpos($key, 'Organization Name') !== false) {
            $contactInfo .= $key.": $value".'<br>'
            ;
        }
        // Otherwise, treat it as other info
        else {
            if(!empty($key)&& $key != 'Frozen Status'&& $key != 'Domain Status' && $key != 'Transfer Status')
                $otherInfo .= $key.": $value".'<br>';
        }
    }
    echo "Domain Info:".'<br>'.$domainName.'<br>';
    echo "Contact Info:".'<br>'.$contactInfo.'<br>';
    echo "Other Info:".'<br>'.$otherInfo;
}
function displayNameservers(array $nameservers) {
    if (empty($nameservers)) {
        echo "No nameservers found."."<br>";
        return;
    }
    else {
        echo '<br>'."Nameservers:"."<br>";
        foreach ($nameservers as $index => $nameserver) {
            echo "$nameserver".'<br>';
        }
    }
}
function displayNameserversAndStatus(array $nameservers, array $statusCodes) {
    if (empty($nameservers)) {
        echo "No nameservers found."."<br>";
        return;
    }
    else {
        echo '<br>'."Nameservers:"."<br>";
        foreach ($nameservers as $index => $nameserver) {
            echo "$nameserver".'<br>';
        }
    }

    if (empty($statusCodes)) {
        echo "No status found."."<br>";
    }
    else {
        echo '<br>'."Status:"."<br>";
        foreach ($statusCodes as $statusCode) {
            echo $statusCode['category'] . '<br>';
        }
    }
}
function displayRegistrar(array $domainArray) {
    if (empty($domainArray)) {
        echo "No Registrar Info Found."."<br>";
    }
    else {
        echo '<br>'."CONTACT INFO:"."<br>";
        foreach ($domainArray as $index => $domainInfo) {
            echo $index.':'."$domainInfo".'<br>';
        }
    }
}
function displayOtherInfo(array $domainArray) {
    if (!empty($domainArray)) {
        echo '<br>'."OTHER INFO:"."<br>";
        foreach ($domainArray as $index => $domainInfo) {
            echo $index.':'."$domainInfo".'<br>';
        }
    }
}

/*
çalışan uzantılar: gov,net,com,org,travel,ru,au,io,edu,cc,name,com.tr,
çalışmayan uzantılar :nl(registrar modifiye edilmeli),co.uk
*/
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WHOIS Lookup</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f3f4f6;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .container {
            background-color: #fff;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            width: 400px;
            max-width: 90%;
            transition: box-shadow 0.3s;
        }

        .container:hover {
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.2);
        }

        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }

        form {
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        input[type="text"] {
            padding: 14px;
            border: none;
            border-radius: 8px;
            background-color: #f9f9f9;
            margin-bottom: 20px;
            width: 100%;
            box-sizing: border-box;
        }

        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            padding: 14px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s, transform 0.3s, box-shadow 0.3s;
            width: 100%;
            box-sizing: border-box;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        input[type="submit"]:hover {
            background-color: #45a049;
            transform: translateX(5px) scale(1.05);
            box-shadow: 0 6px 8px rgba(0, 0, 0, 0.3);
        }

        input[type="submit"]::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.2);
            transition: left 0.3s;
            z-index: 0;
        }

        input[type="submit"]:hover::before {
            left: 0;
        }

        input[type="submit"] span {
            position: relative;
            z-index: 1;
            transition: color 0.3s;
        }

        input[type="submit"]:hover span {
            color: #fff;
        }

        .result {
            margin-top: 30px;
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            transition: box-shadow 0.3s;
        }

        .result:hover {
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.2);
        }

        .result p {
            margin: 0;
            color: #333;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>WHOIS Lookup</h1>
    <form method="post">
        <label>
            <input type="text" name="domain" placeholder="Enter domain name">
        </label>
        <input type="submit" value="Lookup"><span></span>
    </form>
    <div class="result">
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $domain = $_POST['domain'];
            $string = whoIsServerConn($domain);
            $domainExtention = domainSeperator($domain);
            //$parsedInfo = parseTheTRData($string);
            $parsedNameserver = parseTheNameserver($string, $domainExtention);
            $parsedStatusCodes = parseStatusCodes($string, $domainExtention);
            $parsedDomainInfo = parseDomainInfo($string);
            $parsedRegistrarInfo = parseRegistrarInfo($string);
            $parsedOtherInfo = parseOtherInfo($string);

            if (!empty($string)) {
                if ($domainExtention == 'tr' || $domainExtention == 'edu') {
                    //displayParsedData($parsedInfo);
                    //displayNameservers($parsedNameserver);
                    //displayStatusCodes($parsedStatusCodes);
                    displayInfo($parsedDomainInfo, $parsedRegistrarInfo, $parsedOtherInfo, $parsedNameserver, $parsedStatusCodes);
                    die;
                } elseif ($domainExtention != null) {
                    displayInfo($parsedDomainInfo, $parsedRegistrarInfo, $parsedOtherInfo, $parsedNameserver, $parsedStatusCodes);
                    die;
                } else {
                    echo "No information found";
                    die;
                }
            }
        }
        ?>
    </div>
</div>
</body>
</html>
