<?php
	include 'algo.php';
	
	$password_text = "password123";
	
	$hash_output = PasswordHashing::hashPassword($password_text);
	
	$verify_hash = PasswordHashing::verifyPassword($password_text, $hash_output);
	
	echo "Password: ".$password_text;
	echo "Hash output: ".$hash_output;
	echo "Is the password correct? ".$verify_hash;
?>
