crypt4j
=======

A Java implementation of the ```crypt(3)``` function provided in the GNU C 
library (glibc).  This implementation supports the MD5, SHA-256, and SHA-512
variants, but doesn't bother with legacy DES.

Usage
=====

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
}
'''
