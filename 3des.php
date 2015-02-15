<?php

function pad_pkcs5($data) {
    $block_size = mcrypt_get_block_size("tripledes", "cbc");
    $padding_char = $block_size - (strlen($data) % $block_size);
    $data .= str_repeat(chr($padding_char),$padding_char);
    return $data;
}

function unpad_pkcs5($data){
	$length = ord(substr($data, strlen($data)-1));
	$data = substr($data,0,strlen($data)-$length);
	return $data;
}

function triple_des_encode($data, $key, $iv) {
    $td = mcrypt_module_open(MCRYPT_3DES,"", MCRYPT_MODE_CBC, "");
    $key = pack("H48",$key);
    $iv = pack("H16",$iv);
    mcrypt_generic_init($td, $key, $iv);
    $data = pad_pkcs5($data);
    $desResult = mcrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return base64_encode($desResult);
}

function triple_des_decode($data, $key, $iv) {
    $td = mcrypt_module_open(MCRYPT_3DES,"", MCRYPT_MODE_CBC, "");
    $key = pack("H48",$key);
    $iv = pack("H16",$iv);
    mcrypt_generic_init($td, $key, $iv);
    $data = base64_decode($data);
    $desResult = mdecrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    $desResult = unpad_pkcs5($desResult);
    return $desResult;
}

//IV has to be 8bit long
$iv = '2132435465768797';
//Key has to be 24bit long
$key = '000000000000000000000000000000000000000000000000';
//here is the data you want to encrypt
$data = "Jason Grant";

echo "Plan Text:",$data,"\n";
$code = triple_des_encode($data, $key, $iv);
echo "Encrypted Text:",$code,"\n";
$result = triple_des_decode($code, $key, $iv);
echo "Plan Text:",$result,"\n";
