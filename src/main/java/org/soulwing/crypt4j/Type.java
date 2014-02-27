package org.soulwing.crypt4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

enum Type {
  
  SHA256(5, "SHA-256", Sha256Crypt.class),
  SHA512(6, "SHA-512", Sha512Crypt.class);
  
  private final int type;
  private final String algorithm;
  final Class<? extends Crypt> providerClass;
  
  private Type(int type, String algorithm, 
      Class<? extends Crypt> providerClass) {
    this.type = type;
    this.algorithm = algorithm;
    this.providerClass = providerClass;
  }
  
  /**
   * Gets the {@code code} property.
   * @return
   */
  public int getType() {
    return type;
  }

  /**
   * Gets the {@code algorithm} property.
   * @return
   */
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Gets the {@code providerClass} property.
   * @return
   */
  public Class<? extends Crypt> getProviderClass() {
    return providerClass;
  }

  /**
   * Creates a new digest for the algorithm specified for this type.
   * @return message digest
   * @throws NoSuchAlgorithmException
   */
  public MessageDigest newDigest() throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algorithm);  
  }
  
  /**
   * Gets the type instance that corresponds to the type specified by the
   * given salt.
   * @param salt the subject salt
   * @return type instance
   * @throws NoSuchAlgorithmException if no type corresponds to the given salt
   */
  public static Type forSalt(Salt salt) 
      throws NoSuchAlgorithmException {
    for (Type type : Type.values()) {
      if (type.type == salt.getType()) {
        return type;
      }
    }
    throw new NoSuchAlgorithmException(
        new IllegalArgumentException("unsupported type"));
  }
}