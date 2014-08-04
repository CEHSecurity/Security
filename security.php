<?php
//Anti XSS (Cross-site Scripting)
function security($input)
{
    @$input = mysql_real_escape_string($input);
    @$input = strip_tags($input);
    @$input = stripslashes($input);
    return $input;
}

//getBrowser Function
function getBrowser()
{
    $u_agent  = $_SERVER['HTTP_USER_AGENT'];
    $bname    = 'Unknown';
    $platform = 'Unknown';
    $version  = "";
    
    //First get the platform
    if (preg_match('/linux/i', $u_agent)) {
        $platform = 'Linux';
    } elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
        $platform = 'Mac';
    } elseif (preg_match('/windows|win32/i', $u_agent)) {
        $platform = 'Windows';
    }
    
    // Next get the name of the useragent yes seperately and for good reason
    if (preg_match('/MSIE/i', $u_agent) && !preg_match('/Opera/i', $u_agent)) {
        $bname = 'Internet Explorer';
        $ub    = "MSIE";
    } elseif (preg_match('/Firefox/i', $u_agent)) {
        $bname = 'Mozilla Firefox';
        $ub    = "Firefox";
    } elseif (preg_match('/Chrome/i', $u_agent)) {
        $bname = 'Google Chrome';
        $ub    = "Chrome";
    } elseif (preg_match('/Safari/i', $u_agent)) {
        $bname = 'Apple Safari';
        $ub    = "Safari";
    } elseif (preg_match('/Opera/i', $u_agent)) {
        $bname = 'Opera';
        $ub    = "Opera";
    } elseif (preg_match('/Netscape/i', $u_agent)) {
        $bname = 'Netscape';
        $ub    = "Netscape";
    }
    
    // finally get the correct version number
    $known   = array(
        'Version',
        $ub,
        'other'
    );
    $pattern = '#(?<browser>' . join('|', $known) . ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
    if (!preg_match_all($pattern, $u_agent, $matches)) {
        // we have no matching number just continue
    }
    
    // See how many we have
    $i = count($matches['browser']);
    if ($i != 1) {
        //We will have two since we are not using 'other' argument yet
        //See if version is before or after the name
        if (strripos($u_agent, "Version") < strripos($u_agent, $ub)) {
            $version = $matches['version'][0];
        } else {
            $version = $matches['version'][1];
        }
    } else {
        $version = $matches['version'][0];
    }
    
    // Check if we have a number
    if ($version == null || $version == "") {
        $version = "?";
    }
    
    return array(
        'userAgent' => $u_agent,
        'name' => $bname,
        'version' => $version,
        'platform' => $platform,
        'pattern' => $pattern
    );
}
$ua = getBrowser();

//Getting visitor country
function visitor_country()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if (filter_var($client, FILTER_VALIDATE_IP)) {
        $ip = $client;
    } elseif (filter_var($forward, FILTER_VALIDATE_IP)) {
        $ip = $forward;
    } else {
        $ip = $remote;
    }
    
    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=" . $ip));
    
    if ($ip_data && $ip_data->geoplugin_countryName != null) {
        $result = $ip_data->geoplugin_countryName;
    }
    
    return $result;
}

//Checking if phpGuard is enabled
@$query = mysql_query("SELECT * FROM settings");
@$row = mysql_fetch_assoc($query);
if ($row['phpguard_enabled'] == "Yes") {
    
    //Ban System
    $guestip = $_SERVER['REMOTE_ADDR'];
    @$querybanned = mysql_query("SELECT * FROM `bans` WHERE ip='$guestip'");
    @$banned = mysql_num_rows($querybanned);
    @$row = mysql_fetch_array($querybanned);
    @$queryb = mysql_query("SELECT * FROM settings");
    @$rowb = mysql_fetch_assoc($queryb);
    if ($banned > "0") {
        echo '<meta http-equiv="refresh" content="0;url=' . $rowb['banned_page'] . '" />';
    }
    
    //Country Ban
    @$country = visitor_country();
    @$querybanned = mysql_query("SELECT * FROM `bans-country` WHERE country='$country'");
    @$banned = mysql_num_rows($querybanned);
    @$row = mysql_fetch_array($querybanned);
    @$queryb = mysql_query("SELECT * FROM settings");
    @$rowb = mysql_fetch_assoc($queryb);
    if ($banned > "0") {
        echo '<meta http-equiv="refresh" content="0;url=' . $rowb['bannedc_page'] . '" />';
    }
    
    //Anti SQLi (SQL Injection)
    @$query = mysql_query("SELECT * FROM settings");
    @$row = mysql_fetch_assoc($query);
    if ($row['sqli_protection'] == "Yes") {
        
        $array = array(
            "union",
            "sql",
            "mysql",
            "database",
            "cookie",
            "coockie",
            "select",
            "from",
            "where",
            "benchmark",
            "concat",
            "table",
            "into",
            "by",
            "limit",
            "ALL",
            "all",
            "values",
            "exec",
            "shell",
            "truncate",
            "wget",
            "/**/",
            "0x3a",
            "password",
            "-9999999",
            "1,2,3,4,",
            "999",
            "1,2,3,4,5,6,7,8,0,999,",
            "1,2,3,4,5,6,7,8,0,999",
            "BUN",
            "char",
            "S@BUN",
            "null",
            "'%",
            "OR%"
            
        );
        foreach ($array as $d) {
            @$string = security($_SERVER['QUERY_STRING']);
            if (strpos(strtolower($string), $d) !== false) {
                $ip  = $_SERVER['REMOTE_ADDR'];
                $loc = $_SERVER['PHP_SELF'];
                @$browser = $ua['name'];
                @$browser_version = $ua['version'];
                @$os = $ua['platform'];
                @$country = visitor_country();
                $date          = date("d F Y");
                $time          = date("H:i");
                $attacked_page = security('' . $loc . '?' . $string . '');
                $type          = "SQL Injection";
                if ($row['sqli_logging'] == "Yes") {
                    @$queryvalid = mysql_query("SELECT * FROM `hacker-attacks` WHERE ip='$ip' and attacked_page='$attacked_page' and type='SQL Injection' LIMIT 1");
                    @$validator = mysql_num_rows($queryvalid);
                    if ($validator > "0") {
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['sqli_redirect'] . '" />';
                    } else {
                        $log = "INSERT INTO `hacker-attacks` (ip, date, time, attacked_page, type, browser, browser_version, os, country) VALUES ('$ip', '$date', '$time', '$attacked_page', '$type', '$browser', '$browser_version', '$os', '$country')";
                        @$result = mysql_query($log);
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['sqli_redirect'] . '" />';
                    }
                }
                if ($row['sqli_autoban'] == "Yes") {
                    @$bansvalid = mysql_query("SELECT * FROM `bans` WHERE ip='$ip' LIMIT 1");
                    @$bansvalidator = mysql_num_rows($bansvalid);
                    if ($bansvalidator > "0") {
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['sqli_redirect'] . '" />';
                        exit();
                    } else {
                        $log = "INSERT INTO `bans` (ip, date, time, reason, redirect, autoban) VALUES ('$ip', '$date', '$time', '$type', 'No', 'Yes')";
                        @$result = mysql_query($log);
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['sqli_redirect'] . '" />';
                        exit();
                    }
                }
                if ($row['mail_notifier'] == "Yes" && $row['sqli_mail'] == "Yes") {
                    $email   = $row['email'];
                    $to      = $row['email'];
                    $subject = '' . $row['sitename'] . ' - ' . $type . '';
                    $message = '
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta content="en-us" http-equiv="Content-Language">
<title>' . $row['sitename'] . '</title>
<style type="text/css">
body {
	margin:0;
	padding:0;
	background-color:#333333;
	background:#333333;
}
</style>
<style type="text/css"></style></head>
<body bgcolor="#333333" link="#0f75c3" vlink="#0f75c3">
<table align="center" bgcolor="#333333" cellpadding="0" cellspacing="0" style="width: 100%; background:#333333; background-color:#333333; margin:0; padding:0 20px;">
	<tbody><tr>
		<td>
		<table align="center" cellpadding="0" cellspacing="0" style="width: 620px; border-collapse:collapse; text-align:left; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444; margin:0 auto;">
			<!-- Start of logo and top links -->
			<tbody><tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;;line-height:0;">
				<img alt="" height="5" src="./mail-template_files/BottomBackground_Blue_1.png" vspace="0" style="border:0; padding:0; margin:0; line-height:0;" width="620"></td>
			</tr>
			<tr>
				<td style=" width:620px;" valign="top">
					<table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444;">
						<tbody><tr>
							<td bgcolor="#0f75c3" style="width: 320px; padding:10px 0 10px 20px; background:#0f75c3; background-color:#0f75c3; color:#ffffff;" valign="top">
								' . $row['sitename'] . '
							</td>
							<td bgcolor="#0f75c3" style="width: 300px; padding:10px 20px 10px 20px; background:#0f75c3; background-color:#0f75c3; text-align:right; color:#ffffff;" valign="top">
								
							</td>
						</tr>
						<tr>
							<td bgcolor="#FFFFFF" style="width: 320px; padding:20px 0 15px 20px; background:#ffffff; background-color:#ffffff;" valign="middle">
								<p style="padding:0; margin:0; line-height:160%; font-size:18px;">
									<img alt="' . $row['sitename'] . '" height="80" src="http://localhost/phpGuard%20v2/img/logo.png" style="padding:0;border:0;" width="80">
								</p>
							</td>
							<td bgcolor="#FFFFFF" style="width: 300px; padding:20px 20px 15px 20px; background:#ffffff; background-color:#ffffff; text-align:center;" valign="middle">
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>

			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#FFFFFF" style="padding:10px 20px; background:#ffffff;background-color:#ffffff;" valign="top">
					<span style="color:#999999; font-size:8pt;">30 January 2014 at 14:48</span><br>
					<p style="padding:0; margin:0 0 11pt 0;line-height:160%; font-size:18px;">
					' . $type . ' - Details of the Hacker Attack</p>
					<p>IP Address: <b>' . $ip . '</b></p>
					<p>Date: <b>' . $date . '</b> at <b>' . $time . '</b></p>
					<p>Browser & Version:  <b>' . $browser . ' ' . $browser_version . '</b></p>
					<p>Operating System:  <b>' . $os . '</b></p>
					<p>Country:  <b>' . $country . '</b></p>
					<p>Banned: <b>Yes</b></p>
					<p>Type of the attack:  <b>' . $type . '</b> </p>
					<p>Attacked Page:  <b>' . $attacked_page . '</b> </p>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0;line-height:0;">
				</td>
			</tr>
			
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#0f75c3" style="padding:0 20px 15px 20px; background-color:#0f75c3; background:#0f75c3;">
					<table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#FFFFFF;">
						<tbody>
						<tr>
							<td style="padding:20px 0 0 0;" colspan="2">
								Copyright © 2014 ' . $row['sitename'] . '
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0 0 20px 0;line-height:0;">
				</td>
			</tr>
			<!-- End of Footer -->
		</tbody></table>
		</td>
	</tr>
</tbody></table>
</body></html>
				    ';
                    $headers = 'MIME-Version: 1.0' . "\r\n";
                    $headers .= 'Content-type: text/html; charset=utf-8' . "\r\n";
                    $headers .= 'To: ' . $row['email'] . ' <' . $row['email'] . '>' . "\r\n";
                    $headers .= 'From: ' . $row['sitename'] . ' <' . $row['sitename'] . '>' . "\r\n";
                    @mail($to, $subject, $message, $headers);
                }
            }
        }
    }
    
    @$query = mysql_query("SELECT * FROM settings");
    @$row = mysql_fetch_assoc($query);
    if ($row['proxy_protection'] == "Yes") {
        //Anti Proxy
        $proxy_headers = array(
            'HTTP_VIA',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR_IP',
            'VIA',
            'X_FORWARDED_FOR',
            'FORWARDED_FOR',
            'X_FORWARDED',
            'FORWARDED',
            'CLIENT_IP',
            'FORWARDED_FOR_IP',
            'HTTP_PROXY_CONNECTION',
            'HTTP_PC_REMOTE_ADDR',
            'HTTP_X_IMFORWARDS',
            'HTTP_XROXY_CONNECTION'
        );
        foreach ($proxy_headers as $proxy_header) {
            if (isset($_SERVER[$proxy_header])) {
                $ip = $_SERVER['REMOTE_ADDR'];
                @$browser = $ua['name'];
                @$browser_version = $ua['version'];
                @$os = $ua['platform'];
                @$country = visitor_country();
                $date = date("d F Y");
                $time = date("H:i");
                $type = "Proxy";
                if ($row['proxy_logging'] == "Yes") {
                    @$queryvalid2 = mysql_query("SELECT * FROM `hacker-attacks` WHERE ip='$ip' and type='Proxy' LIMIT 1");
                    @$validator2 = mysql_num_rows($queryvalid2);
                    if ($validator2 > "0") {
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['proxy_redirect'] . '" />';
                    } else {
                        $log2 = "INSERT INTO `hacker-attacks` (ip, date, time, attacked_page, type, browser, browser_version, os, country) VALUES ('$ip', '$date', '$time', '$attacked_page', '$type', '$browser', '$browser_version', '$os', '$country')";
                        @$result2 = mysql_query($log2);
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['proxy_redirect'] . '" />';
                    }
                }
                if ($row['proxy_autoban'] == "Yes") {
                    @$bansvalid = mysql_query("SELECT * FROM `bans` WHERE ip='$ip' LIMIT 1");
                    @$bansvalidator = mysql_num_rows($bansvalid);
                    if ($bansvalidator > "0") {
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['proxy_redirect'] . '" />';
                        exit();
                    } else {
                        $log = "INSERT INTO `bans` (ip, date, time, reason, redirect, autoban) VALUES ('$ip', '$date', '$time', '$type', 'No', 'Yes')";
                        @$result = mysql_query($log);
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['proxy_redirect'] . '" />';
                        exit();
                    }
                }
                if ($row['mail_notifier'] == "Yes" && $row['proxy_mail'] == "Yes") {
                    $email   = $row['email'];
                    $to      = $row['email'];
                    $subject = '' . $row['sitename'] . ' - ' . $type . '';
                    $message = '
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta content="en-us" http-equiv="Content-Language">
<title>' . $row['sitename'] . '</title>
<style type="text/css">
body {
	margin:0;
	padding:0;
	background-color:#333333;
	background:#333333;
}
</style>
<style type="text/css"></style></head>
<body bgcolor="#333333" link="#0f75c3" vlink="#0f75c3">
<table align="center" bgcolor="#333333" cellpadding="0" cellspacing="0" style="width: 100%; background:#333333; background-color:#333333; margin:0; padding:0 20px;">
	<tbody><tr>
		<td>
		<table align="center" cellpadding="0" cellspacing="0" style="width: 620px; border-collapse:collapse; text-align:left; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444; margin:0 auto;">
			<!-- Start of logo and top links -->
			<tbody><tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;;line-height:0;">
				<img alt="" height="5" src="./mail-template_files/BottomBackground_Blue_1.png" vspace="0" style="border:0; padding:0; margin:0; line-height:0;" width="620"></td>
			</tr>
			<tr>
				<td style=" width:620px;" valign="top">
					<table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444;">
						<tbody><tr>
							<td bgcolor="#0f75c3" style="width: 320px; padding:10px 0 10px 20px; background:#0f75c3; background-color:#0f75c3; color:#ffffff;" valign="top">
								' . $row['sitename'] . '
							</td>
							<td bgcolor="#0f75c3" style="width: 300px; padding:10px 20px 10px 20px; background:#0f75c3; background-color:#0f75c3; text-align:right; color:#ffffff;" valign="top">
								
							</td>
						</tr>
						<tr>
							<td bgcolor="#FFFFFF" style="width: 320px; padding:20px 0 15px 20px; background:#ffffff; background-color:#ffffff;" valign="middle">
								<p style="padding:0; margin:0; line-height:160%; font-size:18px;">
									<img alt="' . $row['sitename'] . '" height="80" src="http://localhost/phpGuard%20v2/img/logo.png" style="padding:0;border:0;" width="80">
								</p>
							</td>
							<td bgcolor="#FFFFFF" style="width: 300px; padding:20px 20px 15px 20px; background:#ffffff; background-color:#ffffff; text-align:center;" valign="middle">
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>

			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#FFFFFF" style="padding:10px 20px; background:#ffffff;background-color:#ffffff;" valign="top">
					<span style="color:#999999; font-size:8pt;">30 January 2014 at 14:48</span><br>
					<p style="padding:0; margin:0 0 11pt 0;line-height:160%; font-size:18px;">
					' . $type . ' - Details of the Hacker Attack</p>
					<p>IP Address: <b>' . $ip . '</b></p>
					<p>Date: <b>' . $date . '</b> at <b>' . $time . '</b></p>
					<p>Browser & Version:  <b>' . $browser . ' ' . $browser_version . '</b></p>
					<p>Operating System:  <b>' . $os . '</b></p>
					<p>Country:  <b>' . $country . '</b></p>
					<p>Banned: <b>Yes</b></p>
					<p>Type of the attack:  <b>' . $type . '</b> </p>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0;line-height:0;">
				</td>
			</tr>
			
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#0f75c3" style="padding:0 20px 15px 20px; background-color:#0f75c3; background:#0f75c3;">
					<table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#FFFFFF;">
						<tbody>
						<tr>
							<td style="padding:20px 0 0 0;" colspan="2">
								Copyright © 2014 ' . $row['sitename'] . '
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0 0 20px 0;line-height:0;">
				</td>
			</tr>
			<!-- End of Footer -->
		</tbody></table>
		</td>
	</tr>
</tbody></table>
</body></html>
				    ';
                    $headers = 'MIME-Version: 1.0' . "\r\n";
                    $headers .= 'Content-type: text/html; charset=utf-8' . "\r\n";
                    $headers .= 'To: ' . $row['email'] . ' <' . $row['email'] . '>' . "\r\n";
                    $headers .= 'From: ' . $row['sitename'] . ' <' . $row['sitename'] . '>' . "\r\n";
                    @mail($to, $subject, $message, $headers);
                }
            }
        }
    }
    
    @$query = mysql_query("SELECT * FROM settings");
    @$row = mysql_fetch_assoc($query);
    if ($row['ddos_protection'] == "Yes") {
        //Anti DDoS (Distributed Denial of Service Attacks)
        if (!isset($_SESSION)) {
            @session_start();
        }
        if (@$_SESSION['last_session_request'] > time() - 0.3) {
            $ip = $_SERVER['REMOTE_ADDR'];
            @$browser = $ua['name'];
            @$browser_version = $ua['version'];
            @$os = $ua['platform'];
            @$country = visitor_country();
            $date = date("d F Y");
            $time = date("H:i");
            $type = "DDoS";
            if ($row['ddos_logging'] == "Yes") {
                @$queryvalid3 = mysql_query("SELECT * FROM `hacker-attacks` WHERE ip='$ip' and type='DDoS' LIMIT 1");
                @$validator3 = mysql_num_rows($queryvalid3);
                if ($validator3 > "0") {
                    echo '<meta http-equiv="refresh" content="0;url=' . $row['ddos_redirect'] . '" />';
                } else {
                    $log3 = "INSERT INTO `hacker-attacks` (ip, date, time, attacked_page, type, browser, browser_version, os, country) VALUES ('$ip', '$date', '$time', '$attacked_page', '$type', '$browser', '$browser_version', '$os', '$country')";
                    @$result3 = mysql_query($log3);
                    echo '<meta http-equiv="refresh" content="0;url=' . $row['ddos_redirect'] . '" />';
                }
            }
            if ($row['ddos_autoban'] == "Yes") {
                echo 'works ddos autoban';
                @$bansvalid = mysql_query("SELECT * FROM `bans` WHERE ip='$ip' LIMIT 1");
                @$bansvalidator = mysql_num_rows($bansvalid);
                if ($bansvalidator > "0") {
                    echo '<meta http-equiv="refresh" content="0;url=' . $row['ddos_redirect'] . '" />';
                    exit();
                } else {
                    $log = "INSERT INTO `bans` (ip, date, time, reason, redirect, autoban) VALUES ('$ip', '$date', '$time', '$type', 'No', 'Yes')";
                    @$result = mysql_query($log);
                    echo '<meta http-equiv="refresh" content="0;url=' . $row['ddos_redirect'] . '" />';
                    exit();
                }
            }
            if ($row['mail_notifier'] == "Yes" && $row['ddos_mail'] == "Yes") {
                $email   = $row['email'];
                $to      = $row['email'];
                $subject = '' . $row['sitename'] . ' - ' . $type . '';
                $message = '
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta content="en-us" http-equiv="Content-Language">
<title>' . $row['sitename'] . '</title>
<style type="text/css">
body {
	margin:0;
	padding:0;
	background-color:#333333;
	background:#333333;
}
</style>
<style type="text/css"></style></head>
<body bgcolor="#333333" link="#0f75c3" vlink="#0f75c3">
<table align="center" bgcolor="#333333" cellpadding="0" cellspacing="0" style="width: 100%; background:#333333; background-color:#333333; margin:0; padding:0 20px;">
	<tbody><tr>
		<td>
		<table align="center" cellpadding="0" cellspacing="0" style="width: 620px; border-collapse:collapse; text-align:left; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444; margin:0 auto;">
			<!-- Start of logo and top links -->
			<tbody><tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;;line-height:0;">
				<img alt="" height="5" src="./mail-template_files/BottomBackground_Blue_1.png" vspace="0" style="border:0; padding:0; margin:0; line-height:0;" width="620"></td>
			</tr>
			<tr>
				<td style=" width:620px;" valign="top">
					<table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444;">
						<tbody><tr>
							<td bgcolor="#0f75c3" style="width: 320px; padding:10px 0 10px 20px; background:#0f75c3; background-color:#0f75c3; color:#ffffff;" valign="top">
								' . $row['sitename'] . '
							</td>
							<td bgcolor="#0f75c3" style="width: 300px; padding:10px 20px 10px 20px; background:#0f75c3; background-color:#0f75c3; text-align:right; color:#ffffff;" valign="top">
								
							</td>
						</tr>
						<tr>
							<td bgcolor="#FFFFFF" style="width: 320px; padding:20px 0 15px 20px; background:#ffffff; background-color:#ffffff;" valign="middle">
								<p style="padding:0; margin:0; line-height:160%; font-size:18px;">
									<img alt="' . $row['sitename'] . '" height="80" src="http://localhost/phpGuard%20v2/img/logo.png" style="padding:0;border:0;" width="80">
								</p>
							</td>
							<td bgcolor="#FFFFFF" style="width: 300px; padding:20px 20px 15px 20px; background:#ffffff; background-color:#ffffff; text-align:center;" valign="middle">
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>

			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#FFFFFF" style="padding:10px 20px; background:#ffffff;background-color:#ffffff;" valign="top">
					<span style="color:#999999; font-size:8pt;">30 January 2014 at 14:48</span><br>
					<p style="padding:0; margin:0 0 11pt 0;line-height:160%; font-size:18px;">
					' . $type . ' - Details of the Hacker Attack</p>
					<p>IP Address: <b>' . $ip . '</b></p>
					<p>Date: <b>' . $date . '</b> at <b>' . $time . '</b></p>
					<p>Browser & Version:  <b>' . $browser . ' ' . $browser_version . '</b></p>
					<p>Operating System:  <b>' . $os . '</b></p>
					<p>Country:  <b>' . $country . '</b></p>
					<p>Banned: <b>Yes</b></p>
					<p>Type of the attack:  <b>' . $type . '</b> </p>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0;line-height:0;">
				</td>
			</tr>
			
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#0f75c3" style="padding:0 20px 15px 20px; background-color:#0f75c3; background:#0f75c3;">
					<table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#FFFFFF;">
						<tbody>
						<tr>
							<td style="padding:20px 0 0 0;" colspan="2">
								Copyright © 2014 ' . $row['sitename'] . '
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0 0 20px 0;line-height:0;">
				</td>
			</tr>
			<!-- End of Footer -->
		</tbody></table>
		</td>
	</tr>
</tbody></table>
</body></html>
				    ';
                $headers = 'MIME-Version: 1.0' . "\r\n";
                $headers .= 'Content-type: text/html; charset=utf-8' . "\r\n";
                $headers .= 'To: ' . $row['email'] . ' <' . $row['email'] . '>' . "\r\n";
                $headers .= 'From: ' . $row['sitename'] . ' <' . $row['sitename'] . '>' . "\r\n";
                @mail($to, $subject, $message, $headers);
            }
        }
        $_SESSION['last_session_request'] = time();
    }
    
    @$query = mysql_query("SELECT * FROM settings");
    @$row = mysql_fetch_assoc($query);
    if ($row['spam_protection'] == "Yes") {
        //DNSBL Spam Security
        $ip = $_SERVER['REMOTE_ADDR'];
        @$browser = $ua['name'];
        @$browser_version = $ua['version'];
        @$os = $ua['platform'];
        @$country = visitor_country();
        $date         = date("d F Y");
        $time         = date("H:i");
        $type         = "Spam";
        $dnsbl_lookup = array(
            //"dnsbl.solid.net",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "dnsbl.dronebl.org",
            "dnsbl.sorbs.net",
            "zen.spamhaus.org"
        );
        $reverse_ip   = implode(".", array_reverse(explode(".", $ip)));
        foreach ($dnsbl_lookup as $host) {
            if (checkdnsrr($reverse_ip . "." . $host . ".", "A")) {
                @$queryvalid4 = mysql_query("SELECT * FROM `hacker-attacks` WHERE ip='$ip' and type='Spam' LIMIT 1");
                @$validator4 = mysql_num_rows($queryvalid4);
                if ($validator4 > "0") {
                    echo '<meta http-equiv="refresh" content="0;url=' . $row['spam_redirect'] . '" />';
                } else {
                    $log4 = "INSERT INTO `hacker-attacks` (ip, date, time, attacked_page, type, browser, browser_version, os, country) VALUES ('$ip', '$date', '$time', '$attacked_page', '$type', '$browser', '$browser_version', '$os', '$country')";
                    @$result4 = mysql_query($log4);
                    echo '<meta http-equiv="refresh" content="0;url=' . $row['spam_redirect'] . '" />';
                }
                if ($row['spam_autoban'] == "Yes") {
                    @$bansvalid = mysql_query("SELECT * FROM `bans` WHERE ip='$ip' LIMIT 1");
                    @$bansvalidator = mysql_num_rows($bansvalid);
                    if ($bansvalidator > "0") {
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['spam_redirect'] . '" />';
                        exit();
                    } else {
                        $log = "INSERT INTO `bans` (ip, date, time, reason, redirect, autoban) VALUES ('$ip', '$date', '$time', '$type', 'No', 'Yes')";
                        @$result = mysql_query($log);
                        echo '<meta http-equiv="refresh" content="0;url=' . $row['spam_redirect'] . '" />';
                        exit();
                    }
                }
                if ($row['mail_notifier'] == "Yes" && $row['spam_mail'] == "Yes") {
                    $email   = $row['email'];
                    $to      = $row['email'];
                    $subject = '' . $row['sitename'] . ' - ' . $type . '';
                    $message = '
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta content="en-us" http-equiv="Content-Language">
<title>' . $row['sitename'] . '</title>
<style type="text/css">
body {
	margin:0;
	padding:0;
	background-color:#333333;
	background:#333333;
}
</style>
<style type="text/css"></style></head>
<body bgcolor="#333333" link="#0f75c3" vlink="#0f75c3">
<table align="center" bgcolor="#333333" cellpadding="0" cellspacing="0" style="width: 100%; background:#333333; background-color:#333333; margin:0; padding:0 20px;">
	<tbody><tr>
		<td>
		<table align="center" cellpadding="0" cellspacing="0" style="width: 620px; border-collapse:collapse; text-align:left; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444; margin:0 auto;">
			<!-- Start of logo and top links -->
			<tbody><tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;;line-height:0;">
				<img alt="" height="5" src="./mail-template_files/BottomBackground_Blue_1.png" vspace="0" style="border:0; padding:0; margin:0; line-height:0;" width="620"></td>
			</tr>
			<tr>
				<td style=" width:620px;" valign="top">
					<table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444;">
						<tbody><tr>
							<td bgcolor="#0f75c3" style="width: 320px; padding:10px 0 10px 20px; background:#0f75c3; background-color:#0f75c3; color:#ffffff;" valign="top">
								' . $row['sitename'] . '
							</td>
							<td bgcolor="#0f75c3" style="width: 300px; padding:10px 20px 10px 20px; background:#0f75c3; background-color:#0f75c3; text-align:right; color:#ffffff;" valign="top">
								
							</td>
						</tr>
						<tr>
							<td bgcolor="#FFFFFF" style="width: 320px; padding:20px 0 15px 20px; background:#ffffff; background-color:#ffffff;" valign="middle">
								<p style="padding:0; margin:0; line-height:160%; font-size:18px;">
									<img alt="' . $row['sitename'] . '" height="80" src="http://localhost/phpGuard%20v2/img/logo.png" style="padding:0;border:0;" width="80">
								</p>
							</td>
							<td bgcolor="#FFFFFF" style="width: 300px; padding:20px 20px 15px 20px; background:#ffffff; background-color:#ffffff; text-align:center;" valign="middle">
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>

			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#FFFFFF" style="padding:10px 20px; background:#ffffff;background-color:#ffffff;" valign="top">
					<span style="color:#999999; font-size:8pt;">30 January 2014 at 14:48</span><br>
					<p style="padding:0; margin:0 0 11pt 0;line-height:160%; font-size:18px;">
					' . $type . ' - Details of the Hacker Attack</p>
					<p>IP Address: <b>' . $ip . '</b></p>
					<p>Date: <b>' . $date . '</b> at <b>' . $time . '</b></p>
					<p>Browser & Version:  <b>' . $browser . ' ' . $browser_version . '</b></p>
					<p>Operating System:  <b>' . $os . '</b></p>
					<p>Country:  <b>' . $country . '</b></p>
					<p>Banned: <b>Yes</b></p>
					<p>Type of the attack:  <b>' . $type . '</b> </p>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0;line-height:0;">
				</td>
			</tr>
			
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;">
				</td>
			</tr>
			<tr>
				<td bgcolor="#0f75c3" style="padding:0 20px 15px 20px; background-color:#0f75c3; background:#0f75c3;">
					<table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#FFFFFF;">
						<tbody>
						<tr>
							<td style="padding:20px 0 0 0;" colspan="2">
								Copyright © 2014 ' . $row['sitename'] . '
							</td>
						</tr>
					</tbody></table>
				</td>
			</tr>
			<tr>
				<td valign="top" style="height:5px;margin:0;padding:0 0 20px 0;line-height:0;">
				</td>
			</tr>
			<!-- End of Footer -->
		</tbody></table>
		</td>
	</tr>
</tbody></table>
</body></html>
				    ';
                    $headers = 'MIME-Version: 1.0' . "\r\n";
                    $headers .= 'Content-type: text/html; charset=utf-8' . "\r\n";
                    $headers .= 'To: ' . $row['email'] . ' <' . $row['email'] . '>' . "\r\n";
                    $headers .= 'From: ' . $row['sitename'] . ' <' . $row['sitename'] . '>' . "\r\n";
                    @mail($to, $subject, $message, $headers);
                }
            }
        }
    }
    
}
?>
