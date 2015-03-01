crypt4j
=======

[![Build Status](https://travis-ci.org/soulwing/crypt4j.svg?branch=master)](https://travis-ci.org/soulwing/crypt4j)


A Java implementation of the ```crypt(3)``` function provided in the GNU C 
library (glibc).  This implementation supports the MD5, SHA-256, and SHA-512
variants.  Additionally, it supports legacy DES by way of the Commons Codec
library.

Usage
-----

The ```Crypt.crypt``` static method provides the main entry point.  The 
calling arguments are consistent with the ```crypt(3)``` function.

```
import org.soulwing.crypt4j.Crypt;

... {
  // SHA-512 
  String sha512 = Crypt.crypt("Hello world!".toCharArray(), "$6$saltstring");
  assert sha512.equals("$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1");
  
  // SHA-256
  String sha256 = Crypt.crypt("Hello world!".toCharArray(), "$5$saltstring");
  assert sha256.equals("$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");
  
  // MD5
  String md5 = Crypt.crypt("Hello world!".toCharArray(), "$1$saltstring");
  assert md5.equals("$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1");
  
  // DES
  // Requires Commons Codec -- add commons-codec.jar to the classpath
  // or a NoSuchAlgorithmException will be thrown
  String des = Crypt.crypt("Hello world!".toCharArray(), "saltstring");
  assert des.equals("saszt8mUri4AI");
}
```

For simple testing you can simply run it as a jar file, passing the password
and salt string as quoted command line arguments.  

The resulting encrypted password string will be written to standard output.

```
$ java -jar crypt4j.jar 'topsecret' '$6$tRiCkYsAlT'
$6$tRiCkYsAlT$NqxbcVeBHENLGNhXmZY5EB7RZFuLHuzei..4YthS9/SQmwa81pyZBocelML3OXWhSf4ihk9L4VB0dDIdQALtv0
```
