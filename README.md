# PasswordHashing
This is messy and isn't professionally done which is why
we no longer use this.
I've cleaned this up a bit and made it slightly neater.

In my personal opinion, I believe a method similar to this
would be classed as a very secure method for storing passwords.

You can replace the whole PBKDF2 function with your own
in case you want to use something like password_hash().

By default, this is quite CPU intensive. I like high
security so the options are set high.

Feel free to use this how you wish to, just give credit to
the other people at least.

# Requirements
PHP 5.6 and PHP Mcrypt, I think?


# Rights, Licences and what not
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
