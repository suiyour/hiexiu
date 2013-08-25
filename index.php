<?php

# JS相关变量用SESSION存储，这样一用户只产生一个JS文件
if(isset($_GET['js']) && !empty($_GET['js'])){
$js=$_GET['js'];
header('Content-Type: application/javascript'); //application
header('Content-Disposition: attachment; filename="'.$js.'"');
readfile($js);
@unlink($js);
exit;
}


/**
 * +-----------------+-----------------------------------------+
 * |  Script         | dai li modify (修改版) 0.6b29          |
 * |  Author         | (中国)              |
 * |  Last Modified  | 2011/06/29 0:00 AM                      |
 * +-----------------+-----------------------------------------+
 * |  自由使用，责任自负                                       |
 * +-----------------------------------------------------------+
 */

error_reporting(E_ALL);

// CONFIGURABLE OPTIONS

$_config = array
 (
    'url_var_name'        => 'q',
    'flags_var_name'      => 'hl',
    'get_form_name'       => '____pgfa',
    'basic_auth_var_name' => '____pbavn',
    'max_file_size'       => -1,
    'allow_hotlinking'    => 1,
    'upon_hotlink'        => 1,
    'compress_output'     => 0
    );
$_flags = array
 (
    'include_form'        => 0,
    'encrypt_page'        => 1,
    'remove_scripts'      => 0,
    'accept_cookies'      => 1,
    'show_images'         => 1,
    'show_referer'        => 1,
    'rotate13'            => 0,
    'base64_encode'       => 1,
    'strip_meta'          => 1,
    'strip_title'         => 1,
    'session_cookies'     => 1
    );
$_frozen_flags = array
 (
    'include_form'        => 0,
    'encrypt_page'        => 0,
    'remove_scripts'      => 0,
    'accept_cookies'      => 1,
    'show_images'         => 1,
    'show_referer'        => 1,
    'rotate13'            => 1,
    'base64_encode'       => 0,
    'strip_meta'          => 1,
    'strip_title'         => 1,
    'session_cookies'     => 1
    );
$_labels = array
 (
    'include_form'        => array('Include Form', 'Include mini URL-form on every page'),
    'encrypt_page'        => array('encrypted HTML', 'encrypted HTML'),
    'remove_scripts'      => array('Remove Scripts', 'Remove client-side scripting (i.e JavaScript)'),
    'accept_cookies'      => array('Accept Cookies', 'Allow cookies to be stored'),
    'show_images'         => array('Show Images', 'Show images on browsed pages'),
    'show_referer'        => array('Show Referer', 'Show actual referring Website'),
    'rotate13'            => array('Rotate13', 'Use ROT13 encoding on the address'),
    'base64_encode'       => array('Base64', 'Use base64 encodng on the address'),
    'strip_meta'          => array('Strip Meta', 'Strip meta information tags from pages'),
    'strip_title'         => array('Strip Title', 'Strip page title'),
    'session_cookies'     => array('Session Cookies', 'Store cookies for this session only')
    );

$_hosts = array
 (
    // '#^127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost#i'
    );
$_hotlink_domains = array();
$_insert = array();


// END CONFIGURABLE OPTIONS. The ride for you ends here. Close the file.

$_iflags = '';
$_system = array
 (
    'ssl'           => extension_loaded('openssl') && version_compare(PHP_VERSION, '4.3.0', '>='),
    'uploads'       => ini_get('file_uploads'),
    'gzip'          => extension_loaded('zlib') && !ini_get('zlib.output_compression'),
    'stripslashes'  => get_magic_quotes_gpc()
    );
$_proxify           = array('text/html' => 1, 'application/xml+xhtml' => 1, 'application/xhtml+xml' => 1, 'text/css' => 1);
$_version           = '0.6b27';
$_http_host         = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
$_script_url        = 'http' . ((isset($_ENV['HTTPS']) && $_ENV['HTTPS'] == 'on') || $_SERVER['SERVER_PORT'] == 443 ? 's' : '') . '://' . $_http_host . ($_SERVER['SERVER_PORT'] != 80 && $_SERVER['SERVER_PORT'] != 443 ? ':' . $_SERVER['SERVER_PORT'] : '') . $_SERVER['PHP_SELF'];
$_script_base       = substr($_script_url, 0, strrpos($_script_url, '/') + 1);
$_url               = '';
$_url_parts         = array();
$_base              = array();
$_socket            = null;
$_request_method    = $_SERVER['REQUEST_METHOD'];
$_request_headers   = '';
$_cookie            = '';
$_post_body         = '';
$_response_headers  = array();
$_response_keys     = array();
$_http_version      = '';
$_response_code     = 0;
$_content_type      = 'text/html';
$_content_length    = false;
$_content_disp      = '';
$_set_cookie        = array();
$_retry             = false;
$_quit              = false;
$_basic_auth_header = '';
$_basic_auth_realm  = '';
$_auth_creds        = array();
$_response_body     = '';

# 默认代理网站
$autopage = '0'; # 启用为 1
$autourl = 'http://127.0.0.1/p/index.php?mylink=';

# 制作一个书签页
if(isset($_GET['mylink'])){
    $mylink = 'link';
    echo die($mylink);
}

# 定义一个常量 SESS_PREF，它用作密码
session_start();

if(empty($_SESSION['sesspref']))
{
    $sesspref = randstr();
    $_SESSION['sesspref'] = $sesspref;
    }
else $sesspref = $_SESSION['sesspref'];
define('SKEY', $sesspref);

# 浏览器语言
if(!isset($_SERVER["HTTP_ACCEPT_LANGUAGE"]))
{
    $lang = 'en';
    }else{
    preg_match('/^([a-z\-]+)/i', @$_SERVER["HTTP_ACCEPT_LANGUAGE"], $matches);
    $lang = strtolower($matches[1]);
    }

// FUNCTION DECLARATIONS


function show_report($data)
{
    // include $data['which'] . '.inc.php';
    global $_config , $_script_base , $_url_parts , $_content_length , $_url , $_flags , $_labels , $_frozen_flags , $_version ;

    echo '<?xml version="1.0" encoding="utf-8"?>';
    print <<<HEAD
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
<head><title>Web proxy</title>

<style type="text/css">
body, input { font-family: "Bitstream Vera Sans", Arial, Helvetica, sans-serif; color: #44352C; } a { color: #; text-decoration:none; border-bottom: 1px blue dashed; } a:hover { color: #0080FF; } #container { border: 2px #97CCA8 solid; -moz-border-radius: 8px; margin: auto; padding: 5px; width: 713px; } #title { color: #99CC66; margin: 0; } ul#navigation, ul#form { list-style-type: none; padding: 0; margin: 0; } ul#navigation { float: right; } ul#form { clear: both; } ul#navigation li { float: left; margin: 0; padding: 5px 0; border-top: 2px #99CC66 solid; } ul#navigation li a { font-weight: bold; color: #ffffff; background-color: #99CC66; padding: 5px 15px; margin-left: 1px; text-decoration: none; border-bottom: 0 #ffffff solid; } ul#navigation li a:hover { color: #44352C; } ul#form li { width: 700px; } #footer { color: #9B9C83; font-size: 12px;  text-align: right; } #address_bar { border-top: 2px #BFAA9B solid; border-bottom: 3px #44352C solid; background-color: #99CC66; text-align: center; padding: 5px 0; color: #ffffff; } #go { background-color: #ffffff; font-weight: bold; color: #AA8E79; border: 0 #ffffff solid; padding: 2px 5px; } #address_box { width: 500px; } .option { padding: 2px 0; background-color: #EEEBEA; } .option label { border-bottom: 2px #ffffff solid; } form { margin: 0; } #error, #auth { background-color: #AA8E79; border-top: 1px solid #44352C; border-bottom: 1px solid #44352C; width: 700px; clear: both; } #auth { background-color: #94C261; } #error p, #auth p, #auth form { margin: 5px; } 
</style>

<script language="javascript" >

HEAD;

    $body = jsb64encode().'function autojs(){ document.form.' . $_config['url_var_name'] . '.value=window.btoa(document.form.' . $_config['url_var_name'] . '.value); ' .
            'document.form.submit();}'."\n".'</script>'."\n\n".'</head><body onload="document.getElementById(' . "'address_box'" . ').focus()">' .
            '<div id="container"><h1 id="title">Proxy</h1><ul id="navigation"><li><a href="' . $_script_base . '">URL Form</a></li>' .
            '<li><a href="javascript:alert(' . "'cookie managment has not been implemented yet(cookie管理尚未实现)'" . ')">Manage Cookies</a></li></ul>';
    echo $body;
    
    switch ($data['category'])
    {
    case 'auth':
        
        $body = '<div id="auth"><p><b>Enter your username and password for "' . htmlspecialchars($data['realm']) . '" on ' . $_url_parts['host'] . '</b>' .
               '<form method="post" action=""><input type="hidden" name="' . $_config['basic_auth_var_name'] . '" value="' . base64_encode($data['realm']) . '" />' .
               '<label>Username <input type="text" name="username" value="" /></label> <label>Password <input type="password" name="password" value="" /></label>' .
               '<input type="submit" value="Login" /></form></p></div>';
        echo $body;
        break;
    case 'error':
        echo '<div id="error"><p>';
        
        switch ($data['group'])
        {
        case 'url':
            echo '<b>URL Error (' . $data['error'] . ')</b>: ';
            switch ($data['type'])
            {
            case 'internal':
                $message = 'Failed to connect to the specified host. '
                         . 'Possible problems are that the server was not found, the connection timed out, or the connection refused by the host. '
                         . 'Try connecting again and check if the address is correct.';
                break;
            case 'external':
                switch ($data['error'])
                {
                case 1:
                    $message = 'The URL you\'re attempting to access is blacklisted by this server. Please select another URL.';
                    break;
                case 2:
                    $message = 'The URL you entered is malformed. Please check whether you entered the correct URL or not.';
                    break;
                    }
                break;
                }
            break;
        case 'resource':
                echo '<b>Resource Error:</b> ';
                switch ($data['type'])
                {
                case 'file_size':
                    $message = 'The file your are attempting to download is too large.<br />'
                             . 'Maxiumum permissible file size is <b>' . number_format($_config['max_file_size'] / 1048576, 2) . ' MB</b><br />'
                             . 'Requested file size is <b>' . number_format($_content_length / 1048576, 2) . ' MB</b>';
                    break;
                case 'hotlinking':
                    $message = 'It appears that you are trying to access a resource through this proxy from a remote Website.<br />'
                             . 'For security reasons, please use the form below to do so.';
                    break;
                    }
                break;
                }
            
            echo 'An error has occured while trying to browse through the proxy. <br />' . $message . '</p></div>';
            break;
            }
        
        $form = '<form name="form" method="post" action="' . $_SERVER['PHP_SELF'] . '"  onsubmit="autojs();" ><ul id="form">' .
                '<li id="address_bar"><label>Web Address <input id="address_box" type="text" name="' . $_config['url_var_name'] .'" value="';
        //isset($_url) ? $form .= htmlspecialchars($_url) : $form .= '';
        $form .= '" onfocus="this.select()" /></label> <input id="go" type="submit" value="Go" /></li>';      
        echo $form;

        foreach ($_flags as $flag_name => $flag_value)
        {
        if (!$_frozen_flags[$flag_name])
        {
        echo '<li class="option"><label><input type="checkbox" name="' . $_config['flags_var_name'] . '[' . $flag_name . ']"' . ($flag_value ? ' checked="checked"' : '') . ' />' . $_labels[$flag_name][1] . '</label></li>' . "\n";
        }
    }    

    $footer = '</ul></form><div id="footer"><a href="#">home </a>modify (修改版) ' . $_version . '</div></div></body></html>';
    echo $footer;
    exit(0);
    }

//*****************JS代码*******************//



function jsb64encode(){
/*
 * Interfaces:
 * b64 = window.btoa(data);
 * data = window.atob(b64);
 */

$b64en = 'if (typeof(btoa) == "undefined") {' .
    'btoa = function() {' .
    'var base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split("");' .
    'return function(str) {' .
    'var out, i, j, len, r, l, c;' .
    'i = j = 0;' .
    'len = str.length;' .
    'r = len % 3;' .
    'len = len - r;' .
    'l = (len / 3) << 2;' .
    'if (r > 0) {' .
    'l += 4;' .
    '}' .
    'out = new Array(l);' .

    'while (i < len) {' .
    'c = str.charCodeAt(i++) << 16 |' .
    'str.charCodeAt(i++) << 8  |' .
    'str.charCodeAt(i++);' .
    'out[j++] = base64EncodeChars[c >> 18]' .
    '+ base64EncodeChars[c >> 12 & 0x3f]' .
    '+ base64EncodeChars[c >> 6  & 0x3f]' .
    '+ base64EncodeChars[c & 0x3f] ;' .
    '}' .
    'if (r == 1) {' .
    'c = str.charCodeAt(i++);' .
    'out[j++] = base64EncodeChars[c >> 2]' .
    '+ base64EncodeChars[(c & 0x03) << 4]' .
    '+ "==";' .
    '}' .
    'else if (r == 2) {' .
    'c = str.charCodeAt(i++) << 8 |' .
    'str.charCodeAt(i++);' .
    'out[j++] = base64EncodeChars[c >> 10]' .
    ' + base64EncodeChars[c >> 4 & 0x3f]' .
    ' + base64EncodeChars[(c & 0x0f) << 2]' .
    ' + "=";' .
    '}' .
    'return out.join("");' .
    '}' .
    '}();' .
'}';

return $b64en;
}
$XXTEA   = randstr(5);
$toUTF16 = randstr(3);
$decrypt = randstr(2); 
function jsdecode(){
// static class XXTEA
global $XXTEA , $toUTF16 , $decrypt;
$xxtea = 'var '.$XXTEA.' = new function() {' .
    'var delta = 0x9E3779B9;' .

    'function longArrayToString(data, includeLength) {' .
    'var length = data.length;' .
    'var n = (length - 1) << 2;' .
    'if (includeLength) {' .
    'var m = data[length - 1];' .
    'if ((m < n - 3) || (m > n)) return null;' .
    'n = m;' .
    '}' .
    'for (var i = 0; i < length; i++) {' .
    'data[i] = String.fromCharCode(' .
    'data[i] & 0xff,' .
    'data[i] >>> 8 & 0xff,' .
    'data[i] >>> 16 & 0xff,' . 
    'data[i] >>> 24 & 0xff' .
    ');' .
    '}' .
    'if (includeLength) {' .
    'return data.join("").substring(0, n);' .
    '}' .
    'else {' .
    'return data.join("");' .
    '}' .
    '}' .
	
    'function stringToLongArray(string, includeLength) {' .
    'var length = string.length;' .
    'var result = [];' .
    'for (var i = 0; i < length; i += 4) {' .
    'result[i >> 2] = string.charCodeAt(i) |' .
    'string.charCodeAt(i + 1) << 8     |' .
    'string.charCodeAt(i + 2) << 16    |' .
    'string.charCodeAt(i + 3) << 24;' .
    '}' .
    'if (includeLength) {' .
    'result[result.length] = length;' .
    '}' .
    'return result;' .
    '}' .

    'this.'.$decrypt.' = function(string, key) {' .
    'if (string == "") {' .
    'return "";' .
    '}' .
    'var v = stringToLongArray(string, false);' .
    'var k = stringToLongArray(key, false);' .
    'if (k.length < 4) { ' .
    'k.length = 4;' .
    '}' .
    'var n = v.length - 1;' .

    'var z = v[n - 1], y = v[0];' .
    'var mx, e, p, q = Math.floor(6 + 52 / (n + 1)), sum = q * delta & 0xffffffff;' .
    'while (sum != 0) {' .
    'e = sum >>> 2 & 3;' .
    'for (p = n; p > 0; p--) {' .
    'z = v[p - 1];' .
    'mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);' .
    'y = v[p] = v[p] - mx & 0xffffffff;' .
    '}' .
    'z = v[n];' .
    'mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);' .
    'y = v[0] = v[0] - mx & 0xffffffff;' .
    'sum = sum - delta & 0xffffffff;' .
    '}' .

    'return longArrayToString(v, true);' .
    '}' .
'}';


$toutf16 = 'String.prototype.'.$toUTF16.' = function() {' .
    'var str = this;' .
    'if ((str.match(/^[\x00-\x7f]*$/) != null) ||' .
    '(str.match(/^[\x00-\xff]*$/) == null)) {' .
    'return str.toString();' .
    '}' .
    'var out, i, j, len, c, c2, c3, c4, s;' .

    'out = [];' .
    'len = str.length;' .
    'i = j = 0;' .
    'while (i < len) {' .
    'c = str.charCodeAt(i++);' .
    'switch (c >> 4) {' .
    'case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:' .
    '// 0xxx xxxx' ."\n".
    'out[j++] = str.charAt(i - 1);' .
    'break;' .
    'case 12: case 13:' .
    '// 110x xxxx   10xx xxxx' ."\n".
    'c2 = str.charCodeAt(i++);' .
    'out[j++] = String.fromCharCode(((c  & 0x1f) << 6) |' .
    '(c2 & 0x3f));' .
    'break;' .
    'case 14:' .
    '// 1110 xxxx  10xx xxxx  10xx xxxx' ."\n".
    'c2 = str.charCodeAt(i++);' .
    'c3 = str.charCodeAt(i++);' .
    'out[j++] = String.fromCharCode(((c  & 0x0f) << 12) |' .
    '((c2 & 0x3f) <<  6) |' .
    '(c3 & 0x3f));' .
    'break;' .
    'case 15:' .
    'switch (c & 0xf) {' .
    'case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:' .
    '// 1111 0xxx  10xx xxxx  10xx xxxx  10xx xxxx' ."\n".
    'c2 = str.charCodeAt(i++);' .
    'c3 = str.charCodeAt(i++);' .
    'c4 = str.charCodeAt(i++);' .
    's = ((c  & 0x07) << 18) |' .
    '((c2 & 0x3f) << 12) |' .
    '((c3 & 0x3f) <<  6) |' .
    '(c4 & 0x3f) - 0x10000;' .
    'if (0 <= s && s <= 0xfffff) {out[j++] = String.fromCharCode(((s >>> 10) & 0x03ff) | 0xd800,' . 
    '(s     & 0x03ff) | 0xdc00);' .
    '}' .
    'else {' .
    'out[j++] = "?";' .
    '}' .
    'break;' .
    'case 8: case 9: case 10: case 11:' .
    '// 1111 10xx  10xx xxxx  10xx xxxx  10xx xxxx  10xx xxxx' ."\n".
    'i+=4;' .
    'out[j++] = "?";' .
    'break;' .
    'case 12: case 13:' .
    '// 1111 110x  10xx xxxx  10xx xxxx  10xx xxxx  10xx xxxx  10xx xxxx' ."\n".
    'i+=5;' .
    'out[j++] = "?";' .
    'break;' .
    '}' .
    '}' .
    '}' .
    'return out.join("");' .
'}';

return $xxtea."\n".$toutf16;
}


//*****************************************//

function add_cookie($name, $value, $expires = 0)
{
    return rawurlencode(rawurlencode($name)) . '=' . rawurlencode(rawurlencode($value)) . (empty($expires) ? '' : '; expires=' . gmdate('D, d-M-Y H:i:s \G\M\T', $expires)) . '; path=/; domain=.' . $GLOBALS['_http_host'];
    }

function set_post_vars($array, $parent_key = null)
{
    $temp = array();
    
    foreach ($array as $key => $value)
    {
        $key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
        if (is_array($value))
            {
            $temp = array_merge($temp, set_post_vars($value, $key));
            }
        else
            {
            $temp[$key] = urlencode($value);
            }
        }
    
    return $temp;
    }

function set_post_files($array, $parent_key = null)
{
    $temp = array();
    
    foreach ($array as $key => $value)
    {
        $key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
        if (is_array($value))
            {
            $temp = array_merge_recursive($temp, set_post_files($value, $key));
            }
        else if (preg_match('#^([^\[\]]+)\[(name|type|tmp_name)\]#', $key, $m))
            {
            $temp[str_replace($m[0], $m[1], $key)][$m[2]] = $value;
            }
        }
    
    return $temp;
    }

function url_parse($url, & $container)
{
    $temp = @parse_url($url);
    
    if (!empty($temp))
        {
        $temp['port_ext'] = '';
        $temp['base'] = $temp['scheme'] . '://' . $temp['host'];
        
        if (isset($temp['port']))
            {
            $temp['base'] .= $temp['port_ext'] = ':' . $temp['port'];
            }
        else
            {
            $temp['port'] = $temp['scheme'] === 'https' ? 443 : 80;
            }
        
        $temp['path'] = isset($temp['path']) ? $temp['path'] : '/';
        $path = array();
        $temp['path'] = explode('/', $temp['path']);
        
        foreach ($temp['path'] as $dir)
        {
            if ($dir === '..')
            {
                array_pop($path);
                }
            else if ($dir !== '.')
            {
                for ($dir = rawurldecode($dir), $new_dir = '', $i = 0, $count_i = strlen($dir); $i < $count_i; $new_dir .= strspn($dir{$i}, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.+!*\'(),?:@&;=') ? $dir{$i} : rawurlencode($dir{$i}), ++$i);
                $path[] = $new_dir;
                }
            }
        
        $temp['path']     = str_replace('/%7E', '/~', '/' . ltrim(implode('/', $path), '/'));
        $temp['file']     = substr($temp['path'], strrpos($temp['path'], '/') + 1);
        $temp['dir']      = substr($temp['path'], 0, strrpos($temp['path'], '/'));
        $temp['base']    .= $temp['dir'];
        $temp['prev_dir'] = substr_count($temp['path'], '/') > 1 ? substr($temp['base'], 0, strrpos($temp['base'], '/') + 1) : $temp['base'] . '/';
        $container        = $temp;
        
        return true;
        }
    
    return false;
    }

function complete_url($url, $proxify = true)
{
    $url = trim($url);
    
    if ($url === '')
    {
        return '';
        }
    
    $hash_pos = strrpos($url, '#');
    $fragment = $hash_pos !== false ? '#' . substr($url, $hash_pos) : '';
    $sep_pos  = strpos($url, '://');
    
    if ($sep_pos === false || $sep_pos > 5)
    {
        switch ($url{0})
        {
        case '/':
            $url = substr($url, 0, 2) === '//' ? $GLOBALS['_base']['scheme'] . ':' . $url : $GLOBALS['_base']['scheme'] . '://' . $GLOBALS['_base']['host'] . $GLOBALS['_base']['port_ext'] . $url;
            break;
        case '?':
            $url = $GLOBALS['_base']['base'] . '/' . $GLOBALS['_base']['file'] . $url;
            break;
        case '#':
            $proxify = false;
            break;
        case 'm':
            if (substr($url, 0, 7) == 'mailto:')
                {
                $proxify = false;
                break;
                }
            default:
            $url = $GLOBALS['_base']['base'] . '/' . $url;
            }
        }
    
    return $proxify ? "{$GLOBALS['_script_url']}?{$GLOBALS['_config']['url_var_name']}=" . encode_url($url) . $fragment : $url;
    }

function proxify_inline_css($css)
{
    preg_match_all('#url\s*\(\s*(([^)]*(\\\))*[^)]*)(\)|$)?#i', $css, $matches, PREG_SET_ORDER);
    
    for ($i = 0, $count = count($matches); $i < $count; ++$i)
    {
        $css = str_replace($matches[$i][0], 'url(' . proxify_css_url($matches[$i][1]) . ')', $css);
        }
    
    return $css;
    }

function proxify_css($css)
{
    $css = proxify_inline_css($css);
    
    preg_match_all("#@import\s*(?:\"([^\">]*)\"?|'([^'>]*)'?)([^;]*)(;|$)#i", $css, $matches, PREG_SET_ORDER);
    
    for ($i = 0, $count = count($matches); $i < $count; ++$i)
    {
        $delim = '"';
        $url = $matches[$i][2];
        
        if (isset($matches[$i][3]))
            {
            $delim = "'";
            $url = $matches[$i][3];
            }
        
        $css = str_replace($matches[$i][0], '@import ' . $delim . proxify_css_url($matches[$i][1]) . $delim . (isset($matches[$i][4]) ? $matches[$i][4] : ''), $css);
        }
    
    return $css;
    }

function proxify_css_url($url)
{
    $url = trim($url);
    $delim = strpos($url, '"') === 0 ? '"' : (strpos($url, "'") === 0 ? "'" : '');
    
    return $delim . preg_replace('#([\(\),\s\'"\\\])#', '\\$1', complete_url(trim(preg_replace('#\\\(.)#', '$1', trim($url, $delim))))) . $delim;
    }


// SET FLAGS

# 自定义HTML编码
if(isset($_GET['iso']) && !empty($_GET['iso']))
    {
    //$iso = htmlspecialchars(addslashes(trim(ltrim(strtolower($_GET['iso'])))));
    $iso = trim(ltrim(strtolower($_GET['iso'])));
    }

if (isset($_POST[$_config['url_var_name']]) && !isset($_GET[$_config['url_var_name']]) && isset($_POST[$_config['flags_var_name']]))
    {
    foreach ($_flags as $flag_name => $flag_value)
    {
        $_iflags .= isset($_POST[$_config['flags_var_name']][$flag_name]) ? (string)(int)(bool)$_POST[$_config['flags_var_name']][$flag_name] : ($_frozen_flags[$flag_name] ? $flag_value : '0');
        }
    
    $_iflags = base_convert(($_iflags != '' ? $_iflags : '0'), 2, 16);
    }
else if (isset($_GET[$_config['flags_var_name']]) && !isset($_GET[$_config['get_form_name']]) && ctype_alnum($_GET[$_config['flags_var_name']]))
    {
    $_iflags = $_GET[$_config['flags_var_name']];
    }
else if (isset($_COOKIE['flags']) && ctype_alnum($_COOKIE['flags']))
    {
    $_iflags = $_COOKIE['flags'];
    }

if ($_iflags !== '')
{
    $_set_cookie[] = add_cookie('flags', $_iflags, time() + 2419200);
    $_iflags = str_pad(base_convert($_iflags, 16, 2), count($_flags), '0', STR_PAD_LEFT);
    $i = 0;
    
    foreach ($_flags as $flag_name => $flag_value)
    {
        $_flags[$flag_name] = $_frozen_flags[$flag_name] ? $flag_value : (int)(bool)$_iflags{$i};
        $i++;
        }
    }


// DETERMINE URL-ENCODING BASED ON FLAGS

if ($_flags['rotate13'])
{
    function encode_url($url)
    {
        global $iso;
        $url = rawurlencode(str_rot13($url));
        if(isset($iso)) $url = $url . "&iso=$iso";
        return $url;
        }
    function decode_url($url)
    {
        global $iso;
        $url = str_replace(array('&amp;','&#38;'),'&',$url); 
        if(isset($iso)) {
            $url = explode("&iso=",$url);
            $url = $url[0];
            }
        return str_rot13(rawurldecode($url));
        }
    }

else if ($_flags['base64_encode'])
{
    function encode_url($url)
    {
        global $iso;
        $url = rawurlencode(enc($url));
        if(isset($iso) && !empty($iso)) $url = $url . "&iso=$iso";
        return $url;
        }
    function decode_url($url)
    {
        global $iso;
        $url = str_replace(array('&amp;','&#38;'),'&',$url); 
        if(isset($iso)) {
            $url = explode("&iso=",$url);
            $url = $url[0];
            }
        return str_replace(array('&amp;','&#38;'),'&',dec(rawurldecode($url)));
        }
    }

else
    {
    function encode_url($url)
    {
        global $iso;
        $url = rawurlencode($url);
        if(isset($iso)) $url = $url . "&iso=$iso";
        return $url;
        }
     function decode_url($url)
    {
        global $iso;
        $url = str_replace(array('&amp;','&#38;'),'&',$url); 
        if(isset($iso)) {
            $url = explode("&iso=",$url);
            $url = $url[0];
            }
        return rawurldecode($url);
        }
    }

# 追加的函数

# UTF8转成HTML实体
function utf2html($str)
{
    $ret = "";
    $max = strlen($str);
    $last = 0;
    for ($i = 0;$i < $max;$i++){
        $c = $str{$i};
        $c1 = ord($c);
        if ($c1 >> 5 == 6){
            $ret .= substr($str, $last, $i - $last);
            $c1 &= 31; # remove the 3 bit two bytes prefix
            $c2 = ord($str{++$i});
            $c2 &= 63;
            $c2 |= (($c1 & 3) << 6);
            $c1 >>= 2;
            $ret .= "&#" . ($c1 * 0x100 + $c2) . ";";
            $last = $i + 1;
            }
        elseif ($c1 >> 4 == 14){
            $ret .= substr($str, $last, $i - $last);
            $c2 = ord($str{++$i});
            $c3 = ord($str{++$i});
            $c1 &= 15;
            $c2 &= 63;
            $c3 &= 63;
            $c3 |= (($c2 & 3) << 6);
            $c2 >>= 2;
            $c2 |= (($c1 & 15) << 4);
            $c1 >>= 4;
            $ret .= '&#' . (($c1 * 0x10000) + ($c2 * 0x100) + $c3) . ';';
            $last = $i + 1;
            }
        }
    $str = $ret . substr($str, $last, $i);
    return $str;
    }

# JSencode 格式化字符串
function addJsSlashes($str, $flag)
{
     if ($flag){
        $str = addcslashes($str, "\0..\006\010..\012\014..\037\042\047 \134\177..\377");
        }else{
        $str = addcslashes($str, "\0..\006\010..\012\014..\037\042\047 \134");
        }
    return str_replace(array(chr(7), chr(11)), array('\007', '\013'),$str);
    }

# 产生随机字符串
function randstr($len = 16)
{

    $char = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    if(empty($char)) die('Errors: initialise character is NULL');
    if($len > strlen($char)){
        $n = floor($len / strlen($char));
        for($i = 1; $i < $n; $i++){
            $char .= $char;
            }
        }
    $array     = str_split($char, 1);
    $new_array = shuffle($array);
    $char      = join($array);
    $char      = str_split($char, $len);
    return $char[0];
    }

function enc($str)
{
    $key = SKEY;
    $encstr = base64_encode(xxtea_encrypt($str, $key));
    return $encstr;
    }

function dec($encstr)
{
    $key = SKEY;
    $str = xxtea_decrypt(base64_decode($encstr), $key);
    return $str;
    }

# xxtea 加密解密函数
if (!extension_loaded('xxtea'))
{
     function long2str($v, $w){
        $len = count($v);
        $n = ($len - 1) << 2;
        if ($w){
            $m = $v[$len - 1];
            if (($m < $n - 3) || ($m > $n)) return false;
            $n = $m;
            }
        $s = array();
        for ($i = 0; $i < $len; $i++){
            $s[$i] = pack("V", $v[$i]);
            }
        if ($w){
            return substr(join('', $s), 0, $n);
            }
        else{
            return join('', $s);
            }
        }
    
    function str2long($s, $w){
        $v = unpack("V*", $s . str_repeat("\0", (4 - strlen($s) % 4) & 3));
        $v = array_values($v);
        if ($w){
            $v[count($v)] = strlen($s);
            }
        return $v;
        }
    
    function int32($n){
        while ($n >= 2147483648) $n -= 4294967296;
        while ($n <= -2147483649) $n += 4294967296;
        return (int)$n;
        }
    
    function xxtea_encrypt($str, $key){
        if ($str == ""){
            return "";
            }
        $v = str2long($str, true);
        $k = str2long($key, false);
        if (count($k) < 4){
            for ($i = count($k); $i < 4; $i++){
                $k[$i] = 0;
                }
           }
        $n = count($v) - 1;  
        $z = $v[$n];
        $y = $v[0];
        $delta = 0x9E3779B9;
        $q = floor(6 + 52 / ($n + 1));
        $sum = 0;
        while (0 < $q--){
            $sum = int32($sum + $delta);
            $e = $sum >> 2 & 3;
            for ($p = 0; $p < $n; $p++){
                $y = $v[$p + 1];
                $mx = int32((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^ int32(($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
                $z = $v[$p] = int32($v[$p] + $mx);
                }
            $y = $v[0];
            $mx = int32((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^ int32(($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
            $z = $v[$n] = int32($v[$n] + $mx);
            }
        return long2str($v, false);
        }
    
    function xxtea_decrypt($str, $key){
        if ($str == ""){
            return "";
            }
        $v = str2long($str, false);
        $k = str2long($key, false);
        if (count($k) < 4){
		    for ($i = count($k); $i < 4; $i++) {
                $k[$i] = 0;
                }
            }
        $n = count($v) - 1;
        
        $z = $v[$n];
        $y = $v[0];
        $delta = 0x9E3779B9;
        $q = floor(6 + 52 / ($n + 1));
        $sum = int32($q * $delta);
        while ($sum != 0){
            $e = $sum >> 2 & 3;
            for ($p = $n; $p > 0; $p--){
                $z = $v[$p - 1];
                $mx = int32((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^ int32(($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
                $y = $v[$p] = int32($v[$p] - $mx);
                }
            $z = $v[$n];
            $mx = int32((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^ int32(($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
            $y = $v[0] = int32($v[0] - $mx);
            $sum = int32($sum - $delta);
            }
        return long2str($v, true);
        }
    }



// COMPRESS OUTPUT IF INSTRUCTED
/*
if ($_config['compress_output'] && $_system['gzip'])
{
    ob_start('ob_gzhandler');
    }
*/

// STRIP SLASHES FROM GPC IF NECESSARY

if ($_system['stripslashes'])
{
    function _stripslashes($value)
    {
        return is_array($value) ? array_map('_stripslashes', $value) : (is_string($value) ? stripslashes($value) : $value);
        }
    
    $_GET = _stripslashes($_GET);
    $_POST = _stripslashes($_POST);
    $_COOKIE = _stripslashes($_COOKIE);
    }


// FIGURE OUT WHAT TO DO (POST URL-form submit, GET form request, regular request, basic auth, cookie manager, show URL-form)

# 默认代理网站相关代码
if (!isset($_POST[$_config['url_var_name']]) && !isset($_GET[$_config['url_var_name']]) && $autopage == '1')
    {
    header('Location: ' . $_script_url . '?' . $_config['url_var_name'] . '=' . encode_url($autourl) . '&' . $_config['flags_var_name'] . '=2e9');
    exit(0);
    }

# 提交的网址经过编码
if (isset($_POST[$_config['url_var_name']]) && !isset($_GET[$_config['url_var_name']]))
    {
    if(!strstr($_POST[$_config['url_var_name']],'.')){
        $eurl = encode_url(base64_decode($_POST[$_config['url_var_name']]));  
        $_SESSION['supportJS'] = 'true';
        }
else{
        $eurl = encode_url($_POST[$_config['url_var_name']]);
        $_SESSION['supportJS'] = 'false';
        }
    header('Location: ' . $_script_url . '?' . $_config['url_var_name'] . '=' . $eurl . '&' . $_config['flags_var_name'] . '=' . base_convert($_iflags, 2, 16));
    exit(0);
    }

if (isset($_GET[$_config['get_form_name']]))
    {
    $_url = decode_url($_GET[$_config['get_form_name']]);
    $qstr = strpos($_url, '?') !== false ? (strpos($_url, '?') === strlen($_url)-1 ? '' : '&') : '?';
    $arr = explode('&', $_SERVER['QUERY_STRING']);
    
    if (preg_match('#^\Q' . $_config['get_form_name'] . '\E#', $arr[0]))
        {
        array_shift($arr);
        }
    
    $_url .= $qstr . implode('&', $arr);
    }
else if (isset($_GET[$_config['url_var_name']]))
    {
    $_url = decode_url($_GET[$_config['url_var_name']]);
    }
else if (isset($_GET['action']) && $_GET['action'] == 'cookies')
    {
    show_report(array('which' => 'cookies'));
    }
else
    {
    show_report(array('which' => 'index', 'category' => 'entry_form'));
    }

if (isset($_GET[$_config['url_var_name']], $_POST[$_config['basic_auth_var_name']], $_POST['username'], $_POST['password']))
    {
    $_request_method = 'GET';
    $_basic_auth_realm = base64_decode($_POST[$_config['basic_auth_var_name']]);
    $_basic_auth_header = base64_encode($_POST['username'] . ':' . $_POST['password']);
    }


// SET URL

if (strpos($_url, '://') === false)
    {
    $_url = 'http://' . $_url;
    }

if (url_parse($_url, $_url_parts))
    {
    $_base = $_url_parts;
    
    if (!empty($_hosts))
        {
        foreach ($_hosts as $host)
        {
           if (preg_match($host, gethostbyname($_url_parts['host']))) // gethostbyname($host)
                {
                show_report(array('which' => 'index', 'category' => 'error', 'group' => 'url', 'type' => 'external', 'error' => 1));
                }
            }
        }
    }
else
    {
    show_report(array('which' => 'index', 'category' => 'error', 'group' => 'url', 'type' => 'external', 'error' => 2));
    }


// HOTLINKING PREVENTION

if (!$_config['allow_hotlinking'] && isset($_SERVER['HTTP_REFERER']))
    {
    $_hotlink_domains[] = $_http_host;
    $is_hotlinking = true;
    
    foreach ($_hotlink_domains as $host)
    {
        if (preg_match('#^https?\:\/\/(www)?\Q' . $host . '\E(\/|\:|$)#i', trim($_SERVER['HTTP_REFERER'])))
            {
            $is_hotlinking = false;
            break;
            }
        }
    
    if ($is_hotlinking)
    {
        switch ($_config['upon_hotlink'])
        {
        case 1:
            show_report(array('which' => 'index', 'category' => 'error', 'group' => 'resource', 'type' => 'hotlinking'));
            break;
        case 2:
            header('HTTP/1.0 404 Not Found');
            exit(0);
            default:
            header('Location: ' . $_config['upon_hotlink']);
            exit(0);
            }
        }
    }

// OPEN SOCKET TO SERVER

do
{
    $_retry = false;
    $_socket = @fsockopen(($_url_parts['scheme'] === 'https' && $_system['ssl'] ? 'ssl://' : 'tcp://') . $_url_parts['host'], $_url_parts['port'], $err_no, $err_str, 30);
    
    if ($_socket === false)
    {
        show_report(array('which' => 'index', 'category' => 'error', 'group' => 'url', 'type' => 'internal', 'error' => $err_no));
        }
    
     
    // SET REQUEST HEADERS
    
    $_request_headers = $_request_method . ' ' . $_url_parts['path'];
    
    if (isset($_url_parts['query']))
        {
        $_request_headers .= '?';
        $query = preg_split('#([&;])#', $_url_parts['query'], -1, PREG_SPLIT_DELIM_CAPTURE);
        for ($i = 0, $count = count($query); $i < $count; $_request_headers .= implode('=', array_map('urlencode', array_map('urldecode', explode('=', $query[$i])))) . (isset($query[++$i]) ? $query[$i] : ''), $i++);
        }
    
    $_request_headers .= " HTTP/1.0\r\n";
    $_request_headers .= 'Host: ' . $_url_parts['host'] . $_url_parts['port_ext'] . "\r\n";
    $_request_headers .= 'ACCEPT_LANGUAGE: ' . $lang . "\r\n";
    $_request_headers .= 'FORWARDED_FOR: 21.3.63.2'. "\r\n";
    if (isset($_SERVER['HTTP_USER_AGENT']))
        {
        $_request_headers .= 'User-Agent: ' . $_SERVER['HTTP_USER_AGENT'] . "\r\n";
        }
    if (isset($_SERVER['HTTP_ACCEPT']))
        {
        $_request_headers .= 'Accept: ' . $_SERVER['HTTP_ACCEPT'] . "\r\n";
        }
    else
        {
        $_request_headers .= "Accept: */*;q=0.1\r\n";
        }
		 
    if ($_flags['show_referer'] && isset($_SERVER['HTTP_REFERER']) && preg_match('#^\Q' . $_script_url . '?' . $_config['url_var_name'] . '=\E([^&]+)#', $_SERVER['HTTP_REFERER'], $matches))
        {
        $_request_headers .= 'Referer: ' . decode_url($matches[1]) . "\r\n";
        }
    if (!empty($_COOKIE))
        {
        $_cookie = '';
        $_auth_creds = array();
        
        foreach ($_COOKIE as $cookie_id => $cookie_content)
        {
           $cookie_id = explode(';', rawurldecode($cookie_id));
           $cookie_content = explode(';', rawurldecode($cookie_content));
           
            if(isset($cookie_id[3])){
                $cookie_id[3] = dec($cookie_id[3], $key = '');
                $cookie_id[3] = str_replace('.', '_', $cookie_id[3]);
                }
            if ($cookie_id[0] === 'COOKIE')
            {
                $cookie_id[3] = str_replace('_', '.', $cookie_id[3]); //stupid PHP can't have dots in var names

                if (count($cookie_id) < 4 || ($cookie_content[1] == 'secure' && $_url_parts['scheme'] != 'https'))
                    {
                    continue;
                    }
               
                if ((preg_match('#\Q' . $cookie_id[3] . '\E$#i', $_url_parts['host']) || strtolower($cookie_id[3]) == strtolower('.' . $_url_parts['host'])) && preg_match('#^\Q' . $cookie_id[2] . '\E#', $_url_parts['path']))
                    {
                    $_cookie .= ($_cookie != '' ? '; ' : '') . (empty($cookie_id[1]) ? '' : $cookie_id[1] . '=') . $cookie_content[0];
                    }
                }
            else if ($cookie_id[0] === 'AUTH' && count($cookie_id) === 3)
                {
                $cookie_id[2] = str_replace('_', '.', $cookie_id[2]);
               
                if ($_url_parts['host'] . ':' . $_url_parts['port'] === $cookie_id[2])
                {
                    $_auth_creds[$cookie_id[1]] = $cookie_content[0];
                    }
                }
            }
        
        if ($_cookie != '')
        {
            $_request_headers .= "Cookie: $_cookie\r\n";
            }
        }
    if (isset($_url_parts['user'], $_url_parts['pass']))
        {
        $_basic_auth_header = base64_encode($_url_parts['user'] . ':' . $_url_parts['pass']);
        }
    if (!empty($_basic_auth_header))
        {
        $_set_cookie[] = add_cookie("AUTH;{$_basic_auth_realm};{$_url_parts['host']}:{$_url_parts['port']}", $_basic_auth_header);
        $_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
        }
    else if (!empty($_basic_auth_realm) && isset($_auth_creds[$_basic_auth_realm]))
        {
        $_request_headers .= "Authorization: Basic {$_auth_creds[$_basic_auth_realm]}\r\n";
        }
    else if (list($_basic_auth_realm, $_basic_auth_header) = each($_auth_creds))
        {
        $_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
        }
     if ($_request_method == 'POST')
    {
        if (!empty($_FILES) && $_system['uploads'])
            {
            $_data_boundary = '----' . md5(uniqid(rand(), true));
            $array = set_post_vars($_POST);
           
            foreach ($array as $key => $value)
            {
                $_post_body .= "--{$_data_boundary}\r\n";
                $_post_body .= "Content-Disposition: form-data; name=\"$key\"\r\n\r\n";
                $_post_body .= urldecode($value) . "\r\n";
                }
           
            $array = set_post_files($_FILES);
           
            foreach ($array as $key => $file_info)
            {
                $_post_body .= "--{$_data_boundary}\r\n";
                $_post_body .= "Content-Disposition: form-data; name=\"$key\"; filename=\"{$file_info['name']}\"\r\n";
                $_post_body .= 'Content-Type: ' . (empty($file_info['type']) ? 'application/octet-stream' : $file_info['type']) . "\r\n\r\n";
               
                if (is_readable($file_info['tmp_name']))
                    {
                    $handle = fopen($file_info['tmp_name'], 'rb');
                    $_post_body .= fread($handle, filesize($file_info['tmp_name']));
                    fclose($handle);
                    }
               
                $_post_body .= "\r\n";
                }
           
           $_post_body .= "--{$_data_boundary}--\r\n";
           $_request_headers .= "Content-Type: multipart/form-data; boundary={$_data_boundary}\r\n";
           $_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
           $_request_headers .= $_post_body;
           }
        else
            {
            $array = set_post_vars($_POST);
           
            foreach ($array as $key => $value)
            {
                $_post_body .= !empty($_post_body) ? '&' : '';
                $_post_body .= $key . '=' . $value;
                }
            $_request_headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
            $_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
            $_request_headers .= $_post_body;
            $_request_headers .= "\r\n";
            }
        
        $_post_body = '';
        }
    else
        {
        $_request_headers .= "\r\n";
        }
    
    fwrite($_socket, $_request_headers);
    
     
    // PROCESS RESPONSE HEADERS
    
    $_response_headers = $_response_keys = array();
    
    $line = fgets($_socket, 8192);
    
     while (strspn($line, "\r\n") !== strlen($line))
    {
        @list($name, $value) = explode(':', $line, 2);
        $name = trim($name);
        $_response_headers[strtolower($name)][] = trim($value);
        $_response_keys[strtolower($name)] = $name;
        $line = fgets($_socket, 8192);
        }
    
    sscanf(current($_response_keys), '%s %s', $_http_version, $_response_code);
    
    if (isset($_response_headers['content-type']))
        {
        list($_content_type,) = explode(';', str_replace(' ', '', strtolower($_response_headers['content-type'][0])), 2);
        }
    if (isset($_response_headers['content-length']))
        {
        $_content_length = $_response_headers['content-length'][0];
        unset($_response_headers['content-length'], $_response_keys['content-length']);
        }
    if (isset($_response_headers['content-disposition']))   
    {
        $_content_disp = $_response_headers['content-disposition'][0];
        unset($_response_headers['content-disposition'], $_response_keys['content-disposition']);
        }
    if (isset($_response_headers['set-cookie']) && $_flags['accept_cookies'])
        {
        foreach ($_response_headers['set-cookie'] as $cookie)
        {
            $name = $value = $expires = $path = $domain = $secure = $expires_time = '';
           
            preg_match('#^\s*([^=;,\s]*)\s*=?\s*([^;]*)#', $cookie, $match) && list(, $name, $value) = $match;
            preg_match('#;\s*expires\s*=\s*([^;]*)#i', $cookie, $match) && list(, $expires) = $match;
            preg_match('#;\s*path\s*=\s*([^;,\s]*)#i', $cookie, $match) && list(, $path) = $match;
            preg_match('#;\s*domain\s*=\s*([^;,\s]*)#i', $cookie, $match) && list(, $domain) = $match;
            preg_match('#;\s*(secure\b)#i', $cookie, $match) && list(, $secure) = $match;
           
            $expires_time = empty($expires) ? 0 : intval(@strtotime($expires));
            $expires = ($_flags['session_cookies'] && !empty($expires) && time() - $expires_time < 0) ? '' : $expires;
            $path = empty($path) ? '/' : $path;
           
            if (empty($domain))
                {
                $domain = $_url_parts['host'];
                }
            else
                {
                $domain = '.' . strtolower(str_replace('..', '.', trim($domain, '.')));
               
                if ((!preg_match('#\Q' . $domain . '\E$#i', $_url_parts['host']) && $domain != '.' . $_url_parts['host']) || (substr_count($domain, '.') < 2 && $domain{0} == '.'))
                    {
                    continue;
                    }
                }
            $domain = enc($domain);
             if (count($_COOKIE) >= 15 && time() - $expires_time <= 0)
                {
                $_set_cookie[] = add_cookie(current($_COOKIE), '', 1);
                }
           
            $_set_cookie[] = add_cookie("COOKIE;$name;$path;$domain", "$value;$secure", $expires_time);
            }
        }
    if (isset($_response_headers['set-cookie']))
        {
        unset($_response_headers['set-cookie'], $_response_keys['set-cookie']);
        }
    if (!empty($_set_cookie))
        {
        $_response_keys['set-cookie'] = 'Set-Cookie';
        $_response_headers['set-cookie'] = $_set_cookie;
        }
    if (isset($_response_headers['p3p']) && preg_match('#policyref\s*=\s*[\'"]?([^\'"\s]*)[\'"]?#i', $_response_headers['p3p'][0], $matches))
        {
        $_response_headers['p3p'][0] = str_replace($matches[0], 'policyref="' . complete_url($matches[1]) . '"', $_response_headers['p3p'][0]);
        }
     if (isset($_response_headers['refresh']) && preg_match('#([0-9\s]*;\s*URL\s*=)\s*(\S*)#i', $_response_headers['refresh'][0], $matches))
        {
        $_response_headers['refresh'][0] = $matches[1] . complete_url($matches[2]);
        }
     if (isset($_response_headers['location']))
        {
        $_response_headers['location'][0] = complete_url($_response_headers['location'][0]);
        }
     if (isset($_response_headers['uri']))
        {
        $_response_headers['uri'][0] = complete_url($_response_headers['uri'][0]);
        }
     if (isset($_response_headers['content-location']))
        {
        $_response_headers['content-location'][0] = complete_url($_response_headers['content-location'][0]);
        }
     if (isset($_response_headers['connection']))
        {
        unset($_response_headers['connection'], $_response_keys['connection']);
        }
     if (isset($_response_headers['keep-alive']))
        {
        unset($_response_headers['keep-alive'], $_response_keys['keep-alive']);
        }
     if ($_response_code == 401 && isset($_response_headers['www-authenticate']) && preg_match('#basic\s+(?:realm="(.*?)")?#i', $_response_headers['www-authenticate'][0], $matches))
        {
        if (isset($_auth_creds[$matches[1]]) && !$_quit)
            {
            $_basic_auth_realm = $matches[1];
            $_basic_auth_header = '';
            $_retry = $_quit = true;
            }
        else
            {
            show_report(array('which' => 'index', 'category' => 'auth', 'realm' => $matches[1]));
            }
        }
    }
while ($_retry);


// OUTPUT RESPONSE IF NO PROXIFICATION IS NEEDED
// 
if (!isset($_proxify[$_content_type]))
    {
    @set_time_limit(0);
    
    $_response_keys['content-disposition'] = 'Content-Disposition';
    $_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;
    
    if ($_content_length !== false)
    {
        if ($_config['max_file_size'] != -1 && $_content_length > $_config['max_file_size'])
        {
            show_report(array('which' => 'index', 'category' => 'error', 'group' => 'resource', 'type' => 'file_size'));
            }
        
        $_response_keys['content-length'] = 'Content-Length';
        $_response_headers['content-length'][0] = $_content_length;
        }
    
    $_response_headers = array_filter($_response_headers);
    $_response_keys = array_filter($_response_keys);
    
    header(array_shift($_response_keys));
    array_shift($_response_headers);
    
    foreach ($_response_headers as $name => $array)
    {
        foreach ($array as $value)
        {
            header($_response_keys[$name] . ': ' . $value, false);
            }
        }
    
     do
    {
        $data = fread($_socket, 8192);
        echo $data;
        }
    while (isset($data{0}));
    
    fclose($_socket);
    exit(0);
    }

do
{
    $data = @fread($_socket, 8192); // silenced to avoid the "normal" warning by a faulty SSL connection
    $_response_body .= $data;
    }
while (isset($data{0}));

unset($data);
fclose($_socket);


// MODIFY AND DUMP RESOURCE

if ($_content_type == 'text/css')
{
    $_response_body = proxify_css($_response_body);
    $_response_body = preg_replace("/(\/\*)(.*?)(\*\/)/si", "", $_response_body);
    }
else{
    if ($_flags['strip_title'])
    {
        $_response_body = preg_replace('#(<\s*title[^>]*>)(.*?)(<\s*/title[^>]*>)#is', '$1$3', $_response_body);
        }
     if ($_flags['remove_scripts'])
    {
        $_response_body = preg_replace('#<\s*script[^>]*?>.*?<\s*/\s*script\s*>#si', '', $_response_body);
        $_response_body = preg_replace("#(\bon[a-z]+)\s*=\s*(?:\"([^\"]*)\"?|'([^']*)'?|([^'\"\s>]*))?#i", '', $_response_body);
        $_response_body = preg_replace('#<noscript>(.*?)</noscript>#si', "$1", $_response_body);
        }
     if (!$_flags['show_images'])
    {
        $_response_body = preg_replace('#<(img|image)[^>]*?>#si', '', $_response_body);
        }
    
     
    // PROXIFY HTML RESOURCE
    
    $tags = array
     (
        'a'           => array('href'),
        'img'         => array('src', 'longdesc'),
        'image'       => array('src', 'longdesc'),
        'body'        => array('background'),
        'base'        => array('href'),
        'frame'       => array('src', 'longdesc'),
        'iframe'      => array('src', 'longdesc'),
        'head'        => array('profile'),
        'layer'       => array('src'),
        'input'       => array('src', 'usemap'),
        'form'        => array('action'),
        'area'        => array('href'),
        'link'        => array('href', 'src', 'urn'),
        'meta'        => array('content'),
        'param'       => array('value'),
        'applet'      => array('codebase', 'code', 'object', 'archive'),
        'object'      => array('usermap', 'codebase', 'classid', 'archive', 'data'),
        'script'      => array('src'),
        'select'      => array('src'),
        'hr'          => array('src'),
        'table'       => array('background'),
        'tr'          => array('background'),
        'th'          => array('background'),
        'td'          => array('background'),
        'bgsound'     => array('src'),
        'blockquote'  => array('cite'),
        'del'         => array('cite'),
        'embed'       => array('src'),
        'fig'         => array('src', 'imagemap'),
        'ilayer'      => array('src'),
        'ins'         => array('cite'),
        'note'        => array('src'),
        'overlay'     => array('src', 'imagemap'),
        'q'           => array('cite'),
        'ul'          => array('src')
        );
    
     preg_match_all('#(<\s*style[^>]*>)(.*?)(<\s*/\s*style[^>]*>)#is', $_response_body, $matches, PREG_SET_ORDER);
    
     for ($i = 0, $count_i = count($matches); $i < $count_i; ++$i)
    {
        $_response_body = str_replace($matches[$i][0], $matches[$i][1] . proxify_css($matches[$i][2]) . $matches[$i][3], $_response_body);
        }
    
     preg_match_all("#<\s*([a-zA-Z\?-]+)([^>]+)>#S", $_response_body, $matches);
    
    for ($i = 0, $count_i = count($matches[0]); $i < $count_i; ++$i)
    {
        if (!preg_match_all("#([a-zA-Z\-\/]+)\s*(?:=\s*(?:\"([^\">]*)\"?|'([^'>]*)'?|([^'\"\s]*)))?#S", $matches[2][$i], $m, PREG_SET_ORDER))
            {
            continue;
            }
        
        $rebuild = false;
        $extra_html = $temp = '';
        $attrs = array();
        
        for ($j = 0, $count_j = count($m); $j < $count_j; $attrs[strtolower($m[$j][1])] = (isset($m[$j][4]) ? $m[$j][4] : (isset($m[$j][3]) ? $m[$j][3] : (isset($m[$j][2]) ? $m[$j][2] : false))), ++$j);
        
        if (isset($attrs['style']))
            {
            $rebuild = true;
            $attrs['style'] = proxify_inline_css($attrs['style']);
            }
        
        $tag = strtolower($matches[1][$i]);
        
        if (isset($tags[$tag]))
            {
            switch ($tag)
            {
            case 'a':
                if (isset($attrs['href']))
                    {
                    $rebuild = true;
                    $attrs['href'] = complete_url($attrs['href']);
                    }
                break;
            case 'img':
                if (isset($attrs['src']))
                    {
                    $rebuild = true;
                    $attrs['src'] = complete_url($attrs['src']);
                    }
                if (isset($attrs['longdesc']))
                    {
                    $rebuild = true;
                    $attrs['longdesc'] = complete_url($attrs['longdesc']);
                    }
                break;
            case 'form':
                if (isset($attrs['action']))
                    {
                    $rebuild = true;
                  
                    if (trim($attrs['action']) === '')
                        {
                        $attrs['action'] = $_url_parts['path'];
                        }
                    if (!isset($attrs['method']) || strtolower(trim($attrs['method'])) === 'get')
                        {
                        $extra_html = '<input type="hidden" name="' . $_config['get_form_name'] . '" value="' . encode_url(complete_url($attrs['action'], false)) . '" />';
                        $attrs['action'] = '';
                        break;
                        }
                  
                    $attrs['action'] = complete_url($attrs['action']);
                    }
                break;
            case 'base':
                if (isset($attrs['href']))
                    {
                    $rebuild = true;
                    url_parse($attrs['href'], $_base);
                    $attrs['href'] = complete_url($attrs['href']);
                    }
                break;
            case 'meta':
                //$meta_charset = '';
                foreach($attrs as $keys => $values){
                    $keys = strtolower($keys);
                    $values = strtolower($values);
                    if (strstr($keys, 'charset')) $meta_charset = $values;
                    if (strstr($values, 'charset')){
                        $values = str_replace(' ', '', $values);
                        $meta_charset = substr($values, (strpos($values, 'charset=') + 8));
                        //$_charset = explode('charset=',$values);$meta_charset = $_charset[1];
                        }
                    }
               
                if ($_flags['strip_meta'] && isset($attrs['name']))
                    {
                    $_response_body = str_replace($matches[0][$i], '', $_response_body);
                    }
                if (isset($attrs['http-equiv'], $attrs['content']) && preg_match('#\s*refresh\s*#i', $attrs['http-equiv']))
                    {
                    if (preg_match('#^(\s*[0-9]*\s*;\s*url=)(.*)#i', $attrs['content'], $content))
                        {
                        $rebuild = true;
                        $attrs['content'] = $content[1] . complete_url(trim($content[2], '"\''));
                        }
                    }
                break;
            case 'head':

                if (isset($attrs['profile']))
                    {
                    $rebuild = true;
                    $attrs['profile'] = implode(' ', array_map('complete_url', explode(' ', $attrs['profile'])));
                    }
                break;
            case 'applet':
                if (isset($attrs['codebase']))
                    {
                    $rebuild = true;
                    $temp = $_base;
                    url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
                    unset($attrs['codebase']);
                    }
                if (isset($attrs['code']) && strpos($attrs['code'], '/') !== false)
                    {
                    $rebuild = true;
                    $attrs['code'] = complete_url($attrs['code']);
                    }
                if (isset($attrs['object']))
                    {
                    $rebuild = true;
                    $attrs['object'] = complete_url($attrs['object']);
                    }
                if (isset($attrs['archive']))
                    {
                    $rebuild = true;
                    $attrs['archive'] = implode(',', array_map('complete_url', preg_split('#\s*,\s*#', $attrs['archive'])));
                    }
                if (!empty($temp))
                    {
                    $_base = $temp;
                    }
                break;
            case 'object':
                if (isset($attrs['usemap']))
                    {
                    $rebuild = true;
                    $attrs['usemap'] = complete_url($attrs['usemap']);
                    }
                if (isset($attrs['codebase']))
                    {
                    $rebuild = true;
                    $temp = $_base;
                    url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
                    unset($attrs['codebase']);
                    }
                if (isset($attrs['data']))
                    {
                    $rebuild = true;
                    $attrs['data'] = complete_url($attrs['data']);
                    }
                if (isset($attrs['classid']) && !preg_match('#^clsid:#i', $attrs['classid']))
                    {
                    $rebuild = true;
                    $attrs['classid'] = complete_url($attrs['classid']);
                    }
                if (isset($attrs['archive']))
                    {
                    $rebuild = true;
                    $attrs['archive'] = implode(' ', array_map('complete_url', explode(' ', $attrs['archive'])));
                    }
                if (!empty($temp))
                    {
                    $_base = $temp;
                    }
                break;
            case 'param':
                if (isset($attrs['valuetype'], $attrs['value']) && strtolower($attrs['valuetype']) == 'ref' && preg_match('#^[\w.+-]+://#', $attrs['value']))
                    {
                    $rebuild = true;
                    $attrs['value'] = complete_url($attrs['value']);
                    }
                break;
            case 'frame':
            case 'iframe':
                if (isset($attrs['src']))
                    {
                    $rebuild = true;
                    $attrs['src'] = complete_url($attrs['src']) . '&nf=1';
                    }
                if (isset($attrs['longdesc']))
                    {
                    $rebuild = true;
                    $attrs['longdesc'] = complete_url($attrs['longdesc']);
                    }
                break;
            default:
                foreach ($tags[$tag] as $attr)
                {
                    if (isset($attrs[$attr]))
                        {
                        $rebuild = true;
                        $attrs[$attr] = complete_url($attrs[$attr]);
                        }
                    }
                break;
                }
            }
        
        if ($rebuild)
        {
            $new_tag = "<$tag";
            foreach ($attrs as $name => $value)
            {
                $delim = strpos($value, '"') && !strpos($value, "'") ? "'" : '"';
                $_value = strtolower($value);
                if(strstr($_value, '<br') or strstr($_value, '<b') or strstr($_value, '<p') or strstr($_value, '<u') or strstr($_value, '<font') or strstr($_value, '<clockquote')){
                    $new_tag .= ' ' . $name . ($value !== false ? '=' . $delim . $value : '');
                    }else{
                    $new_tag .= ' ' . $name . ($value !== false ? '=' . $delim . $value . $delim : '');
                    }
                }
           
            $_response_body = str_replace($matches[0][$i], $new_tag . '>' . $extra_html, $_response_body);
            }
        }
    }

if ($_flags['include_form'] && !isset($_GET['nf']))
    {
    $enc_url_var = 'document.form.' . $GLOBALS['_config']['url_var_name'] . '.value';
    $_url_form = '<div style="margin:0;text-align:center;border-bottom:1px #725554;color:#000000;background-color:#99CC66;font-size:12px;font-weight:bold;font-family:Bitstream Vera Sans,arial,sans-serif;padding:0px;">'
     . '<script type="text/javascript" >'.jsb64encode().'</script>'   
     . '<form name="form" method="post" action="' . $_script_url . '" onsubmit="' . $enc_url_var . '=window.btoa(' . $enc_url_var . ');">'
     . ' <label for="____' . $_config['url_var_name'] . '"><a href="' . $_url . '">address</a>:</label> <input id="____' . $_config['url_var_name'] . '" type="text" size="80" name="' . $_config['url_var_name'] . '" value="' . $_url . '" />'
     . ' <input type="submit" name="go" value="go" />'
     . ' [<a href="' . $_script_url . '?' . $_config['url_var_name'] . '=' . encode_url($_url_parts['prev_dir']) . ' ">updir</a>, <a href="' . $_script_base . '">homepage</a>]'
     . '<br /><hr />';
        
    foreach ($_flags as $flag_name => $flag_value)
        {
        if(!$_frozen_flags[$flag_name]){
            $_url_form .= '<label><input type="checkbox" name="' . $_config['flags_var_name'] . '[' . $flag_name . ']"' . ($flag_value ? ' checked="checked"' : '') . ' /> ' . $_labels[$flag_name][0] . '</label> ';
            }
        }   
    $_url_form .= '</form></div>';
    $_response_body = preg_replace('#\<\s*body(.*?)\>#si', "$0\n$_url_form" , $_response_body, 1);
    }

# 非加密时被指定了编码
if ($_content_type == 'text/html' && !$_flags['encrypt_page'] && isset($iso) && !empty($iso)){
    $_response_body = @iconv($iso, 'UTF-8//IGNORE//TRANSLIT', $_response_body);
    header("Content-type: text/html;charset=utf-8");
    }
	
# 加密 HTML
if ($_content_type == 'text/html' && $_flags['encrypt_page']){

    # 判断 charset
    if (isset($iso) && !empty($iso)) $charset = $iso; 
    elseif($_response_body == @iconv('UTF-8', 'UTF-8//IGNORE//TRANSLIT', $_response_body)) $charset = 'utf-8';
    elseif(!empty($meta_charset)){
        $charset = $meta_charset;
        if(strstr($charset, 'gb2312')) $charset = 'GBK';
        if(strstr($charset, 'iso-8859-1') && $lang == 'zh-cn') $charset = 'GBK';
        if(strstr($charset, 'utf-8')) $charset = 'ANSI';
    }else{
        $charset = 'ANSI';
        }
    
    # 转为 UTF-8 
    if($charset !== 'utf-8' && $charset !== 'ANSI'){
        // if(extension_loaded('mbstring')) $_response_body = mb_convert_encoding($_response_body, 'UTF-8', $charset);
        // elseif(extension_loaded('iconv')) $_response_body = iconv($charset, 'UTF-8//IGNORE//TRANSLIT', $_response_body);
        $_response_body = @iconv($charset, 'UTF-8//IGNORE//TRANSLIT', $_response_body);
        }
    
    # HTML 实体之后，加密 HTML
    if(!isset($_SESSION['supportJS'])) $_SESSION['supportJS'] = 'true';
    if($charset !== 'ANSI' && $_SESSION['supportJS'] == 'true'){
        $head = '';	
        $offset = preg_match('#</head[^>]*>(.)#is', $_response_body, $tmp, PREG_OFFSET_CAPTURE) ? $tmp[1][1] : 0;
        if($offset){ # 如果非零值
            $head = substr($_response_body, 0, $offset-7);
            $_response_body = substr($_response_body, $offset);
            }
        $head  = preg_replace("/(\/\*)(.*?)(\*\/)/si", "", $head);
        $head  = utf2html($head);    //echo '&#'.ord('b').';';    
        $str_host = explode('.', $_url_parts['host']);
        $n_str_host = count($str_host);
        $domain_host = @$str_host[$n_str_host-2] . '.' . @$str_host[$n_str_host-1];
        if($_url_parts['host'] != $_SERVER['HTTP_HOST']) $head  = str_replace($domain_host,$_SERVER['HTTP_HOST'],$head);

/*
        //********************* 以文件方式加载 JS ********************* //
        //date_default_timezone_set('Asia/Shanghai');
        $dir = './';
        $dh = opendir($dir);
        while (($file = readdir($dh)) !== false) {
            if(filetype($dir . $file) !== "dir"){
                $ftime = filectime($dir.$file);
                if((time() - $ftime) > 60 && strstr($file,'.js')) unlink($dir.$file);
                //echo "$file \n";
            }
        }
        closedir($dh);

        $jsfn  = randstr(rand(2,4)).'.js';
        file_put_contents($jsfn,jsdecode());
        //$head .= '<script language="javascript" src = "'.$jsfn.'"></script>';
	$head .= '<script language="javascript" type="text/javascript" src = "index.php?js='.$jsfn.'"></script></head>'."\n\n";
	//****************************************** //
*/
		
        $head .= '<script language="javascript" type="text/javascript">'.jsdecode()."\n\n".'</script></head>'; 


        $key            = rand(1,20);
        $jsenc          = randstr(2);
        $jsdec          = randstr(1);
        $jsstr          = randstr(rand(2,6));
        $_response_body = xxtea_encrypt($_response_body, $key);
        $_response_body = addJsSlashes($_response_body, $flag = true);
        $_response_body = '<script language="javascript" type="text/javascript"> var '.$jsenc.'="'.$_response_body.'";var '.$jsdec.'='.$XXTEA.';'.
                          'var '.$jsstr.'='.$jsdec.'.'.$decrypt.'('.$jsenc.', "'.$key.'").'.$toUTF16.'();document.write('.$jsstr.');</script>';
		$_response_body = $head.$_response_body;	   
        }
    elseif($charset !== 'ANSI' && $_SESSION['supportJS'] == 'false') $_response_body = utf2html($_response_body);
	}
$_response_keys['content-disposition']       = 'Content-Disposition';
$_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;
$_response_keys['content-length']            = 'Content-Length';
$_response_headers['content-length'][0]      = strlen($_response_body);
$_response_headers                           = array_filter($_response_headers);
$_response_keys                              = array_filter($_response_keys);

header(array_shift($_response_keys));
array_shift($_response_headers);

foreach ($_response_headers as $name => $array)
{
     foreach ($array as $value)
    {
        header($_response_keys[$name] . ': ' . $value, false);
        }
    }

if ($_config['compress_output'] && $_system['gzip'] && isset($_SERVER['HTTP_ACCEPT_ENCODING']) && !$_flags['encrypt_page']){
        header('Content-Encoding: deflate');
        $_response_body = gzdeflate($_response_body, 9);
    }
if ($_content_type == 'text/html' && $_flags['encrypt_page'] && $charset !== 'ANSI')  header("Content-type: text/html;charset=utf-8");
echo $_response_body;



?>















