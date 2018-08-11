<?php
/*
	
	-----------------------------------------------------------
	
	WebDeflect Password Hashing Method
	
	Version: 1.1
	Version Update Time: 11/08/2018 @ 02:30
	
	Created by: Kieran Willis
	Description: This script is to be used for the
	hashing of passwords and password verification
	for WebDeflect ( https://webdeflect.com ).
	
	This is messy and isn't professionally done which is why
	we no longer use this.
	I've cleaned this up a bit and made it slightly neater.
	
	You can replace the whole PBKDF2 function with your own
	in case you want to use something like password_hash().
	
	By default, this is quite CPU intensive. I like high
	security so the options are set high.
	
	Feel free to use this how you wish to, just give credit to
	the other people at least.
	
	-----------------------------------------------------------
	
	Rights for the AES implementation in PHP (along with the
	AES counter (CTR) mode implementation in PHP) goes to
	Chris Veness over at https://www.movable-type.co.uk
	He's got a lot of cool stuff on his site so go and check
	it out!
	
	The rights for PHP go to the fantastic PHP Group, whom
	without we would not be able to create such great websites.
	https://php.net
	
	PBKDF2 is part of the Public-Key Cryptography Standards
	(PKCS) brought to us by the fantastic people over at
	RSA Security LLC (formerly RSA Laboratories)
	https://www.rsa.com
	
	The PHP PBKDF2 was originally created by https://defuse.ca
	With improvements by http://www.variations-of-shadow.com
	
	-----------------------------------------------------------
	
	Requirements:
	PHP 5.6
	PHP Mcrypt
	I think that's all?
	
	-----------------------------------------------------------
	
	Things to note:
	You can use sha1, sha224, sha256, sha384, sha512, ripemd160, ripemd256, ripemd320, whirlpool as your HASH_ALGORITHM.
	I would recommend you use sha256, sha384, sha512 or whirlpool for HASH_ALGORITHM!
	The output of the hashing/AES encryption is encoded using Base64 so that you can actually store it somewhere such as a database.
	Keep OUTPUT_BYTES the same length as what your HASH_ALGORITHM will output! Search the output length of what you put for HASH_ALGORITHM if you need help.
	Use an online password generator (one which uses JavaScript to generate and serve the password) to use as your AES_PASSWORD - Make sure it's long too!
	I've randomized the number of PBKDF2 iterations because why not? If you want them to always be the same, put the same number for ITERATIONS_MIN and ITERATIONS_MAX.
	
	-----------------------------------------------------------
	
	How to use:
	
	To hash a password:
	PasswordHashing::hashPassword($plaintext);
	
	To verify a password:
	PasswordHashing::verifyPassword($plaintext, $hashedPassword);
	
	$plaintext = the input password, the unencrypted, plain password
	$hashedPassword = The hashed password from your database/where ever
	
*/

// Change this... obviously...
$AES_PASSWORD = "vzagRxeSp7tDhWqb3j9qUBdxahnuA28vxmfLXHAahOFzXyBAAai1VQYtzgy3x8CmeSBoNSHKTulEAgaWhpa71lHrQVxriBeHDjdNZByij9mOAdsQ90jtoMXczZ6y2XKq";

// These settings can be changed freely, it will work with old hashes perfectly fine.
$HASH_ALGORITHM = "whirlpool"; // The hashing algorithm to use.
$SALT_BYTES = "128"; // The number of bytes to add as a salt.
$OUTPUT_BYTES = "128"; // The number of bytes to save from the output hash.
$ITERATIONS_MIN = "3500"; // The minimum number of PBKDF2 iterations.
$ITERATIONS_MAX = "4500"; // The maximum number of PBKDF2 iterations.
// END OF CONFIGURATION!

// Modifying anything under this line WILL cause issues.
Class PasswordHashing
{
	public static function encryptHash($input)
	{
		global $AES_PASSWORD;
		return AesCtr::encrypt(PBKDF2_STORAGE::create_hash($input), $AES_PASSWORD, 256);
	}
	public static function decryptHash($input, $compare)
	{
		global $AES_PASSWORD;
		return PBKDF2_STORAGE::verify_password($input, AesCtr::decrypt($compare, $AES_PASSWORD, 256));
	}
}
class InvalidHashException extends Exception {}
class CannotPerformOperationException extends Exception {}
class PBKDF2_STORAGE
{
  global $HASH_ALGORITHM;
  global $SALT_BYTES;
  global $OUTPUT_BYTES;
  const PBKDF2_HASH_ALGORITHM = $HASH_ALGORITHM;
  const PBKDF2_SALT_BYTES = $SALT_BYTES;
  const PBKDF2_OUTPUT_BYTES = $OUTPUT_BYTES;
  const HASH_SECTIONS = 5;
  const HASH_ALGORITHM_INDEX = 0;
  const HASH_ITERATION_INDEX = 1;
  const HASH_SIZE_INDEX = 2;
  const HASH_SALT_INDEX = 3;
  const HASH_PBKDF2_INDEX = 4;
  public static function create_hash($password)
  {
      if (!\is_string($password)) {
        throw new InvalidArgumentException("create_hash(): Expected a string");
      }
      if (\function_exists('random_bytes')) {
        try {
          $salt_raw = \random_bytes(self::PBKDF2_SALT_BYTES);
        } catch (Error $e) {
          $salt_raw = false;
        } catch (Exception $e) {
          $salt_raw = false;
        } catch (TypeError $e) {
          $salt_raw = false;
        }
      } else {
        $salt_raw = \mcrypt_create_iv(self::PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM);
      }
      if ($salt_raw === false) {
        throw new CannotPerformOperationException("Random number generator failed. Not safe to proceed.");
      }
	  global $ITERATIONS_MIN;
	  global $ITERATIONS_MAX;
	  $PBKDF2_iterations = mt_rand($ITERATIONS_MIN, $ITERATIONS_MAX);
	  $PBKDF2_Output = self::pbkdf2(self::PBKDF2_HASH_ALGORITHM, $password, $salt_raw, $PBKDF2_iterations, self::PBKDF2_OUTPUT_BYTES, true);
      return bin2hex(self::PBKDF2_HASH_ALGORITHM.":".$PBKDF2_iterations.":".self::PBKDF2_OUTPUT_BYTES.":".\base64_encode($salt_raw).":".\base64_encode($PBKDF2_Output));
    }
    public static function verify_password($password, $hash)
    {
        if (!\is_string($password) || !\is_string($hash)) {
            throw new InvalidArgumentException("verify_password(): Expected two strings");
        }
        $params = \explode(":", hex2bin($hash));
        if (\count($params) !== self::HASH_SECTIONS) {
            throw new InvalidHashException("Fields are missing from the password hash.");
        }
        $pbkdf2 = \base64_decode($params[self::HASH_PBKDF2_INDEX], true);
        if ($pbkdf2 === false) {
            throw new InvalidHashException("Base64 decoding of pbkdf2 output failed.");
        }
        $salt_raw = \base64_decode($params[self::HASH_SALT_INDEX], true);
        if ($salt_raw === false) {
            throw new InvalidHashException("Base64 decoding of salt failed.");
        }
        $storedOutputSize = (int) $params[self::HASH_SIZE_INDEX];
        if (self::ourStrlen($pbkdf2) !== $storedOutputSize) {
            throw new InvalidHashException("PBKDF2 output length doesn't match stored output length.");
        }
        $iterations = (int) $params[self::HASH_ITERATION_INDEX];
        if ($iterations < 1) {
            throw new InvalidHashException("Invalid number of iterations. Must be >= 1.");
        }
        return self::slow_equals($pbkdf2, self::pbkdf2($params[self::HASH_ALGORITHM_INDEX], $password, $salt_raw, $iterations, self::ourStrlen($pbkdf2), true));
    }
    public static function slow_equals($a, $b)
    {
        if (!\is_string($a) || !\is_string($b)) {
            throw new InvalidArgumentException("slow_equals(): expected two strings");
        }
        if (\function_exists('hash_equals')) {
            return \hash_equals($a, $b);
        }
        $diff = self::ourStrlen($a) ^ self::ourStrlen($b);
        for($i = 0; $i < self::ourStrlen($a) && $i < self::ourStrlen($b); $i++) {
            $diff |= \ord($a[$i]) ^ \ord($b[$i]);
        }
        return $diff === 0;
    }
    public static function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        if (!\is_string($algorithm)) {
            throw new InvalidArgumentException("pbkdf2(): algorithm must be a string");
        }
        if (!\is_string($password)) {
            throw new InvalidArgumentException("pbkdf2(): password must be a string");
        }
        if (!\is_string($salt)) {
            throw new InvalidArgumentException("pbkdf2(): salt must be a string");
        }
        $count += 0;
        $key_length += 0;
        $algorithm = \strtolower($algorithm);
        if (!\in_array($algorithm, \hash_algos(), true)) {
            throw new CannotPerformOperationException("Invalid or unsupported hash algorithm.");
        }
        $ok_algorithms = array("sha1", "sha224", "sha256", "sha384", "sha512", "ripemd160", "ripemd256", "ripemd320", "whirlpool");
        if (!\in_array($algorithm, $ok_algorithms, true)) {
            throw new CannotPerformOperationException("Algorithm is not a secure cryptographic hash function.");
        }
        if ($count <= 0 || $key_length <= 0) {
            throw new CannotPerformOperationException("Invalid PBKDF2 parameters.");
        }
        if (\function_exists("hash_pbkdf2")) {
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return \hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }
        $hash_length = self::ourStrlen(\hash($algorithm, "", true));
        $block_count = \ceil($key_length / $hash_length);
        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            $last = $salt . \pack("N", $i);
            $last = $xorsum = \hash_hmac($algorithm, $last, $password, true);
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = \hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }
        if($raw_output) {
            return self::ourSubstr($output, 0, $key_length);
        } else {
            return \bin2hex(self::ourSubstr($output, 0, $key_length));
        }
    }
    private static function ourStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_strlen');
        }
        if (!\is_string($str)) {
            throw new InvalidArgumentException("ourStrlen() expects a string");
        }
        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            if ($length === false) {
                throw new CannotPerformOperationException();
            }
            return $length;
        } else {
            return \strlen($str);
        }
    }
    private static function ourSubstr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_substr');
        }
        if (!\is_string($str)) {
            throw new InvalidArgumentException("ourSubstr() expects a string");
        }
        if ($exists) {
            if (!isset($length)) {
                if ($start >= 0) {
                    $length = self::ourStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }
            return \mb_substr($str, $start, $length, '8bit');
        }
        if (isset($length)) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
    }
}
Class Aes
{
    public static function cipher($input, $w)
    {
        $Nb = 4;
        $Nr = 14;
        $state = array();
        for ($i = 0; $i < 4 * $Nb; $i++) $state[$i % 4][floor($i / 4)] = $input[$i];
        $state = self::addRoundKey($state, $w, 0, $Nb);
        for ($round = 1; $round < $Nr; $round++) {
            $state = self::subBytes($state, $Nb);
            $state = self::shiftRows($state, $Nb);
            $state = self::mixColumns($state, $Nb);
            $state = self::addRoundKey($state, $w, $round, $Nb);
        }
        $state = self::subBytes($state, $Nb);
        $state = self::shiftRows($state, $Nb);
        $state = self::addRoundKey($state, $w, $Nr, $Nb);
        $output = array(4 * $Nb);
        for ($i = 0; $i < 4 * $Nb; $i++) $output[$i] = $state[$i % 4][floor($i / 4)];
        return $output;
    }
    private static function addRoundKey($state, $w, $rnd, $Nb)
    {
        for ($r = 0; $r < 4; $r++) {
            for ($c = 0; $c < $Nb; $c++) $state[$r][$c] ^= $w[$rnd * 4 + $c][$r];
        }
        return $state;
    }
    private static function subBytes($s, $Nb)
    {
        for ($r = 0; $r < 4; $r++) {
            for ($c = 0; $c < $Nb; $c++) $s[$r][$c] = self::$sBox[$s[$r][$c]];
        }
        return $s;
    }
    private static function shiftRows($s, $Nb)
    {
        $t = array(4);
        for ($r = 1; $r < 4; $r++) {
            for ($c = 0; $c < 4; $c++) $t[$c] = $s[$r][($c + $r) % $Nb];
            for ($c = 0; $c < 4; $c++) $s[$r][$c] = $t[$c];
        }
        return $s;
    }
    private static function mixColumns($s, $Nb)
    {
        for ($c = 0; $c < 4; $c++) {
            $a = array(4);
            $b = array(4);
            for ($i = 0; $i < 4; $i++) {
                $a[$i] = $s[$i][$c];
                $b[$i] = $s[$i][$c] & 0x80 ? $s[$i][$c] << 1 ^ 0x011b : $s[$i][$c] << 1;
            }
            $s[0][$c] = $b[0] ^ $a[1] ^ $b[1] ^ $a[2] ^ $a[3];
            $s[1][$c] = $a[0] ^ $b[1] ^ $a[2] ^ $b[2] ^ $a[3];
            $s[2][$c] = $a[0] ^ $a[1] ^ $b[2] ^ $a[3] ^ $b[3];
            $s[3][$c] = $a[0] ^ $b[0] ^ $a[1] ^ $a[2] ^ $b[3];
        }
        return $s;
    }
    public static function keyExpansion($key)
    {
        $Nb = 4;
        $Nk = 8;
        $Nr = 14;
        $w = array();
        $temp = array();
        for ($i = 0; $i < $Nk; $i++) {
            $r = array($key[4 * $i], $key[4 * $i + 1], $key[4 * $i + 2], $key[4 * $i + 3]);
            $w[$i] = $r;
        }
        for ($i = $Nk; $i < ($Nb * ($Nr + 1)); $i++) {
            $w[$i] = array();
            for ($t = 0; $t < 4; $t++) $temp[$t] = $w[$i - 1][$t];
            if ($i % $Nk == 0) {
                $temp = self::subWord(self::rotWord($temp));
                for ($t = 0; $t < 4; $t++) $temp[$t] ^= self::$rCon[$i / $Nk][$t];
            } else if ($Nk > 6 && $i % $Nk == 4) {
                $temp = self::subWord($temp);
            }
            for ($t = 0; $t < 4; $t++) $w[$i][$t] = $w[$i - $Nk][$t] ^ $temp[$t];
        }
        return $w;
    }
    private static function subWord($w)
    {
        for ($i = 0; $i < 4; $i++) $w[$i] = self::$sBox[$w[$i]];
        return $w;
    }
    private static function rotWord($w)
    {
        $tmp = $w[0];
        for ($i = 0; $i < 3; $i++) $w[$i] = $w[$i + 1];
        $w[3] = $tmp;
        return $w;
    }
    private static $sBox = array(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);
    private static $rCon = array(
        array(0x00, 0x00, 0x00, 0x00),
        array(0x01, 0x00, 0x00, 0x00),
        array(0x02, 0x00, 0x00, 0x00),
        array(0x04, 0x00, 0x00, 0x00),
        array(0x08, 0x00, 0x00, 0x00),
        array(0x10, 0x00, 0x00, 0x00),
        array(0x20, 0x00, 0x00, 0x00),
        array(0x40, 0x00, 0x00, 0x00),
        array(0x80, 0x00, 0x00, 0x00),
        array(0x1b, 0x00, 0x00, 0x00),
        array(0x36, 0x00, 0x00, 0x00));
}
Class AesCtr extends Aes
{
    public static function encrypt($plaintext, $password, $nBits)
    {
        $blockSize = 16;
        if (!($nBits == 128 || $nBits == 192 || $nBits == 256)) return '';
        $nBytes = $nBits / 8;
        $pwBytes = array();
        for ($i = 0; $i < $nBytes; $i++) $pwBytes[$i] = ord(substr($password, $i, 1)) & 0xff;
        $key = Aes::cipher($pwBytes, Aes::keyExpansion($pwBytes));
        $key = array_merge($key, array_slice($key, 0, $nBytes - 16));
        $counterBlock = array();
        $nonce = floor(microtime(true) * 1000);
        $nonceMs = $nonce % 1000;
        $nonceSec = floor($nonce / 1000);
        $nonceRnd = floor(rand(0, 0xffff));
        for ($i = 0; $i < 2; $i++) $counterBlock[$i] = self::urs($nonceMs, $i * 8) & 0xff;
        for ($i = 0; $i < 2; $i++) $counterBlock[$i + 2] = self::urs($nonceRnd, $i * 8) & 0xff;
        for ($i = 0; $i < 4; $i++) $counterBlock[$i + 4] = self::urs($nonceSec, $i * 8) & 0xff;
        $ctrTxt = '';
        for ($i = 0; $i < 8; $i++) $ctrTxt .= chr($counterBlock[$i]);
        $keySchedule = Aes::keyExpansion($key);
        $blockCount = ceil(strlen($plaintext) / $blockSize);
        $ciphertxt = array();
        for ($b = 0; $b < $blockCount; $b++) {
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c] = self::urs($b, $c * 8) & 0xff;
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c - 4] = self::urs($b / 0x100000000, $c * 8);
            $cipherCntr = Aes::cipher($counterBlock, $keySchedule);
            $blockLength = $b < $blockCount - 1 ? $blockSize : (strlen($plaintext) - 1) % $blockSize + 1;
            $cipherByte = array();
            for ($i = 0; $i < $blockLength; $i++) {
                $cipherByte[$i] = $cipherCntr[$i] ^ ord(substr($plaintext, $b * $blockSize + $i, 1));
                $cipherByte[$i] = chr($cipherByte[$i]);
            }
            $ciphertxt[$b] = implode('', $cipherByte);
        }
        $ciphertext = $ctrTxt . implode('', $ciphertxt);
        $ciphertext = base64_encode($ciphertext);
        return $ciphertext;
    }
    public static function decrypt($ciphertext, $password, $nBits)
    {
        $blockSize = 16;
        if (!($nBits == 128 || $nBits == 192 || $nBits == 256)) return '';
        $ciphertext = base64_decode($ciphertext);
        $nBytes = $nBits / 8;
        $pwBytes = array();
        for ($i = 0; $i < $nBytes; $i++) $pwBytes[$i] = ord(substr($password, $i, 1)) & 0xff;
        $key = Aes::cipher($pwBytes, Aes::keyExpansion($pwBytes));
        $key = array_merge($key, array_slice($key, 0, $nBytes - 16));
        $counterBlock = array();
        $ctrTxt = substr($ciphertext, 0, 8);
        for ($i = 0; $i < 8; $i++) $counterBlock[$i] = ord(substr($ctrTxt, $i, 1));
        $keySchedule = Aes::keyExpansion($key);
        $nBlocks = ceil((strlen($ciphertext) - 8) / $blockSize);
        $ct = array();
        for ($b = 0; $b < $nBlocks; $b++) $ct[$b] = substr($ciphertext, 8 + $b * $blockSize, 16);
        $ciphertext = $ct;
        $plaintxt = array();
        for ($b = 0; $b < $nBlocks; $b++) {
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c] = self::urs($b, $c * 8) & 0xff;
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c - 4] = self::urs(($b + 1) / 0x100000000 - 1, $c * 8) & 0xff;
            $cipherCntr = Aes::cipher($counterBlock, $keySchedule);
            $plaintxtByte = array();
            for ($i = 0; $i < strlen($ciphertext[$b]); $i++) {
                $plaintxtByte[$i] = $cipherCntr[$i] ^ ord(substr($ciphertext[$b], $i, 1));
                $plaintxtByte[$i] = chr($plaintxtByte[$i]);
            }
            $plaintxt[$b] = implode('', $plaintxtByte);
        }
        $plaintext = implode('', $plaintxt);
        return $plaintext;
    }
    private static function urs($a, $b)
    {
        $a &= 0xffffffff;
        $b &= 0x1f;
        if ($a & 0x80000000 && $b > 0) {
            $a = ($a >> 1) & 0x7fffffff;
            $a = $a >> ($b - 1);
        } else {
            $a = ($a >> $b);
        }
        return $a;
    }
}
?>
