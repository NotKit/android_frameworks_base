package android.security.keystore;

import android.annotation.Nullable;
import android.security.Credentials;
import android.security.KeyPairGeneratorSpec;
import android.security.KeyStore;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keymaster.KeyCharacteristics;
import android.security.keymaster.KeymasterArguments;
import android.security.keymaster.KeymasterDefs;
import android.text.TextUtils;
import android.util.Log;

import com.android.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.org.bouncycastle.asn1.ASN1InputStream;
import com.android.org.bouncycastle.asn1.ASN1Integer;
import com.android.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.org.bouncycastle.asn1.DERBitString;
import com.android.org.bouncycastle.asn1.DERInteger;
import com.android.org.bouncycastle.asn1.DERNull;
import com.android.org.bouncycastle.asn1.DERSequence;
import com.android.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.android.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.org.bouncycastle.asn1.x509.Certificate;
import com.android.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.org.bouncycastle.asn1.x509.TBSCertificate;
import com.android.org.bouncycastle.asn1.x509.Time;
import com.android.org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import com.android.org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.android.org.bouncycastle.jce.X509Principal;
import com.android.org.bouncycastle.jce.provider.X509CertificateObject;
import com.android.org.bouncycastle.x509.X509V3CertificateGenerator;

import libcore.util.EmptyArray;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashSet;
import java.util.Set;

/**
 * @hide
 **/
public class SoterKeyStoreKeyPairRSAGeneratorSpi extends KeyPairGeneratorSpi {

    /*
     * These must be kept in sync with system/security/keystore/defaults.h
     */

    /* RSA */
    private static final int RSA_DEFAULT_KEY_SIZE = 2048;
    private static final int RSA_MIN_KEY_SIZE = 512;
    private static final int RSA_MAX_KEY_SIZE = 8192;

    private final int mOriginalKeymasterAlgorithm;

    private KeyStore mKeyStore;

    private KeyGenParameterSpec mSpec;

    private String mEntryAlias;
    private boolean mEncryptionAtRestRequired;
    private
    @KeyProperties.KeyAlgorithmEnum String mJcaKeyAlgorithm;
    private int mKeymasterAlgorithm = -1;
    private int mKeySizeBits;
    private SecureRandom mRng;

    private int[] mKeymasterPurposes;
    private int[] mKeymasterBlockModes;
    private int[] mKeymasterEncryptionPaddings;
    private int[] mKeymasterSignaturePaddings;
    private int[] mKeymasterDigests;

    private BigInteger mRSAPublicExponent;
    //for soter
    private boolean isForSoter = false;
    private boolean isAutoSignedWithAttkWhenGetPublicKey = false;
    private boolean isAutoSignedWithCommonkWhenGetPublicKey = false;
    private String mAutoSignedKeyNameWhenGetPublicKey = "";
    private boolean isSecmsgFidCounterSignedWhenSign = false;
    private boolean isAutoAddCounterWhenGetPublicKey = false;
    private boolean isNeedNextAttk = false;

    //protected
    public SoterKeyStoreKeyPairRSAGeneratorSpi() {
        mOriginalKeymasterAlgorithm = KeymasterDefs.KM_ALGORITHM_RSA;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new IllegalArgumentException(
                KeyGenParameterSpec.class.getName() +
                " required to initialize this KeyPairGenerator");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        resetAll();

        boolean success = false;
        try {
            if (params == null) {
                throw new InvalidAlgorithmParameterException(
                        "Must supply params of type " + KeyGenParameterSpec.class.getName()
                        + " or " + KeyPairGeneratorSpec.class.getName());
            }

            KeyGenParameterSpec spec;
            boolean encryptionAtRestRequired = false;
            int keymasterAlgorithm = mOriginalKeymasterAlgorithm;
            if (params instanceof KeyGenParameterSpec) {
                spec = (KeyGenParameterSpec) params;
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported params class: " + params.getClass().getName()
                        + ". Supported: " + KeyGenParameterSpec.class.getName()
                        + ", " + KeyPairGeneratorSpec.class.getName());
            }

            mEntryAlias = SoterUtil.getPureKeyAliasFromKeyName(spec.getKeystoreAlias());
            mSpec = spec;
            mKeymasterAlgorithm = keymasterAlgorithm;
            mEncryptionAtRestRequired = encryptionAtRestRequired;
            mKeySizeBits = spec.getKeySize();
            initAlgorithmSpecificParameters();
            if (mKeySizeBits == -1) {
                mKeySizeBits = getDefaultKeySize(keymasterAlgorithm);
            }
            checkValidKeySize(keymasterAlgorithm, mKeySizeBits);

            if (spec.getKeystoreAlias() == null) {
                throw new InvalidAlgorithmParameterException("KeyStore entry alias not provided");
            }

            String jcaKeyAlgorithm;
            try {
                jcaKeyAlgorithm = KeyProperties.KeyAlgorithm.fromKeymasterAsymmetricKeyAlgorithm(
                        keymasterAlgorithm);
                mKeymasterPurposes = KeyProperties.Purpose.allToKeymaster(spec.getPurposes());
                mKeymasterBlockModes = KeyProperties.BlockMode.allToKeymaster(spec.getBlockModes());
                mKeymasterEncryptionPaddings = KeyProperties.EncryptionPadding.allToKeymaster(
                        spec.getEncryptionPaddings());
                if (((spec.getPurposes() & KeyProperties.PURPOSE_ENCRYPT) != 0)
                        && (spec.isRandomizedEncryptionRequired())) {
                    for (int keymasterPadding : mKeymasterEncryptionPaddings) {
                        if (!KeymasterUtils
                                .isKeymasterPaddingSchemeIndCpaCompatibleWithAsymmetricCrypto(
                                        keymasterPadding)) {
                            throw new InvalidAlgorithmParameterException(
                                    "Randomized encryption (IND-CPA) required but may be violated"
                                    + " by padding scheme: "
                                    + KeyProperties.EncryptionPadding.fromKeymaster(
                                            keymasterPadding)
                                    + ". See " + KeyGenParameterSpec.class.getName()
                                    + " documentation.");
                        }
                    }
                }
                mKeymasterSignaturePaddings = KeyProperties.SignaturePadding.allToKeymaster(
                        spec.getSignaturePaddings());
                if (spec.isDigestsSpecified()) {
                    mKeymasterDigests = KeyProperties.Digest.allToKeymaster(spec.getDigests());
                } else {
                    mKeymasterDigests = EmptyArray.INT;
                }

                // Check that user authentication related parameters are acceptable. This method
                // will throw an IllegalStateException if there are issues (e.g., secure lock screen
                // not set up).
                KeymasterUtils.addUserAuthArgs(new KeymasterArguments(),
                                mSpec.isUserAuthenticationRequired(),
                                mSpec.getUserAuthenticationValidityDurationSeconds(),
                                false,
                                true);
            } catch (IllegalArgumentException | IllegalStateException e) {
                throw new InvalidAlgorithmParameterException(e);
            }

            mJcaKeyAlgorithm = jcaKeyAlgorithm;
            mRng = random;
            mKeyStore = KeyStore.getInstance();
            success = true;
        } finally {
            if (!success) {
                resetAll();
            }
        }
    }

    private void resetAll() {
        mEntryAlias = null;
        mJcaKeyAlgorithm = null;
        mKeymasterAlgorithm = -1;
        mKeymasterPurposes = null;
        mKeymasterBlockModes = null;
        mKeymasterEncryptionPaddings = null;
        mKeymasterSignaturePaddings = null;
        mKeymasterDigests = null;
        mKeySizeBits = 0;
        mSpec = null;
        mRSAPublicExponent = null;
        mEncryptionAtRestRequired = false;
        mRng = null;
        mKeyStore = null;

        // soter
        isForSoter = false;
        isAutoSignedWithAttkWhenGetPublicKey = false;
        isAutoSignedWithCommonkWhenGetPublicKey = false;
        mAutoSignedKeyNameWhenGetPublicKey = "";
        isSecmsgFidCounterSignedWhenSign = false;
        isAutoAddCounterWhenGetPublicKey = false;
        isNeedNextAttk = false;
    }

    private void initAlgorithmSpecificParameters() throws InvalidAlgorithmParameterException {
        AlgorithmParameterSpec algSpecificSpec = mSpec.getAlgorithmParameterSpec();
        BigInteger publicExponent = RSAKeyGenParameterSpec.F4;
        if (algSpecificSpec instanceof RSAKeyGenParameterSpec) {
            Log.i(SoterUtil.TAG,
                    "initAlgorithmSpecificParameters: starting initing RSAKeyGenParameterSpec");
            RSAKeyGenParameterSpec rsaSpec = (RSAKeyGenParameterSpec) algSpecificSpec;
            if (mKeySizeBits == -1) {
                mKeySizeBits = rsaSpec.getKeysize();
            } else if (mKeySizeBits != rsaSpec.getKeysize()) {
                throw new InvalidAlgorithmParameterException("RSA key size must match "
                        + " between " + mSpec + " and " + algSpecificSpec
                        + ": " + mKeySizeBits + " vs " + rsaSpec.getKeysize());
            }
            publicExponent = rsaSpec.getPublicExponent();
            if (publicExponent.compareTo(BigInteger.ZERO) < 1) {
                throw new InvalidAlgorithmParameterException(
                        "RSA public exponent must be positive: " + publicExponent);
            }
            if (publicExponent.compareTo(KeymasterArguments.UINT64_MAX_VALUE) > 0) {
                throw new InvalidAlgorithmParameterException(
                        "Unsupported RSA public exponent: " + publicExponent
                        + ". Maximum supported value: " + KeymasterArguments.UINT64_MAX_VALUE);
            }
        }
        mRSAPublicExponent = publicExponent;
        SoterRSAKeyGenParameterSpec soterSpec =
                SoterUtil.convertKeyNameToParameterSpec(mSpec.getKeystoreAlias());
        if (soterSpec != null) {
            isForSoter = soterSpec.isForSoter();
            isAutoSignedWithAttkWhenGetPublicKey = soterSpec.isAutoSignedWithAttkWhenGetPublicKey();
            isAutoSignedWithCommonkWhenGetPublicKey =
                    soterSpec.isAutoSignedWithCommonkWhenGetPublicKey();
            mAutoSignedKeyNameWhenGetPublicKey = soterSpec.getAutoSignedKeyNameWhenGetPublicKey();
            isSecmsgFidCounterSignedWhenSign = soterSpec.isSecmsgFidCounterSignedWhenSign();
            isAutoAddCounterWhenGetPublicKey = soterSpec.isAutoAddCounterWhenGetPublicKey();
            isNeedNextAttk = soterSpec.isNeedUseNextAttk();
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (mKeyStore == null || mSpec == null) {
            throw new IllegalStateException("Not initialized");
        }

        final int flags = (mEncryptionAtRestRequired) ? KeyStore.FLAG_ENCRYPTED : 0;
        if (((flags & KeyStore.FLAG_ENCRYPTED) != 0)
                && (mKeyStore.state() != KeyStore.State.UNLOCKED)) {
            throw new IllegalStateException(
                    "Encryption at rest using secure lock screen credential requested for key pair"
                    + ", but the user has not yet entered the credential");
        }

        byte[] additionalEntropy =
                KeyStoreCryptoOperationUtils.getRandomBytesToMixIntoKeystoreRng(
                        mRng, (mKeySizeBits + 7) / 8);

        final String privateKeyAlias = Credentials.USER_PRIVATE_KEY + mEntryAlias;
        boolean success = false;
        try {
            Credentials.deleteAllTypesForAlias(mKeyStore, mEntryAlias);
            generateKeystoreKeyPair(
                    privateKeyAlias, constructKeyGenerationArguments(), additionalEntropy, flags);
            KeyPair keyPair = loadKeystoreKeyPair(privateKeyAlias);

            storeCertificate(
                    Credentials.USER_CERTIFICATE,
                    generateSelfSignedCertificateBytes(keyPair),
                    flags,
                    "Failed to store certificate");

            success = true;
            return keyPair;
        } finally {
            if (!success) {
                Credentials.deleteAllTypesForAlias(mKeyStore, mEntryAlias);
            }
        }
    }

    private static volatile SecureRandom sRng;

    private void addAlgorithmSpecificParameters(KeymasterArguments keymasterArgs) {
        if(mRSAPublicExponent != null) {
            keymasterArgs.addUnsignedLong(
                                  KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT, mRSAPublicExponent);
        }

        if (isForSoter) {
            keymasterArgs.addBoolean(KeymasterDefs.KM_TAG_SOTER_IS_FROM_SOTER);
            keymasterArgs.addUnsignedInt(KeymasterDefs.KM_TAG_SOTER_UID,
                    (long) android.os.Process.myUid());
        }

        if (isAutoSignedWithAttkWhenGetPublicKey) {
            keymasterArgs.addBoolean(
                    KeymasterDefs.KM_TAG_SOTER_IS_AUTO_SIGNED_WITH_ATTK_WHEN_GET_PUBLIC_KEY);
        }

        if (isAutoSignedWithCommonkWhenGetPublicKey) {
            keymasterArgs.addBoolean(
                    KeymasterDefs.KM_TAG_SOTER_IS_AUTO_SIGNED_WITH_COMMON_KEY_WHEN_GET_PUBLIC_KEY);

            if (!TextUtils.isEmpty(mAutoSignedKeyNameWhenGetPublicKey)) {
                // Here just pass the key alias to KeyStore daemon and
                // it will retrieve the real key. Charset is UTF-8.
                keymasterArgs.addBytes(
                        KeymasterDefs.KM_TAG_SOTER_AUTO_SIGNED_COMMON_KEY_WHEN_GET_PUBLIC_KEY,
                        (Credentials.USER_PRIVATE_KEY + mAutoSignedKeyNameWhenGetPublicKey)
                        .getBytes());
            }
        }

        if (isAutoAddCounterWhenGetPublicKey) {
            keymasterArgs.addBoolean(
                    KeymasterDefs.KM_TAG_SOTER_AUTO_ADD_COUNTER_WHEN_GET_PUBLIC_KEY);
        }

        if (isSecmsgFidCounterSignedWhenSign) {
            keymasterArgs.addBoolean(
                    KeymasterDefs.KM_TAG_SOTER_IS_SECMSG_FID_COUNTER_SIGNED_WHEN_SIGN);
        }

        if (isNeedNextAttk) {
            keymasterArgs.addBoolean(KeymasterDefs.KM_TAG_SOTER_USE_NEXT_ATTK);
        }
    }

    private X509Certificate generateSelfSignedCertificate(PrivateKey privateKey,
            PublicKey publicKey) throws CertificateParsingException, IOException {
        String signatureAlgorithm =
                getCertificateSignatureAlgorithm(mKeymasterAlgorithm, mKeySizeBits, mSpec);
        if (signatureAlgorithm == null) {
            // Key cannot be used to sign a certificate
            return generateSelfSignedCertificateWithFakeSignature(publicKey);
        } else {
            // Key can be used to sign a certificate
            try {
                return generateSelfSignedCertificateWithValidSignature(
                        privateKey, publicKey, signatureAlgorithm);
            } catch (Exception e) {
                // Failed to generate the self-signed certificate with valid signature. Fall back
                // to generating a self-signed certificate with a fake signature. This is done for
                // all exception types because we prefer key pair generation to succeed and end up
                // producing a self-signed certificate with an invalid signature to key pair
                // generation failing.
                return generateSelfSignedCertificateWithFakeSignature(publicKey);
            }
        }
    }

    private byte[] generateSelfSignedCertificateBytes(KeyPair keyPair) throws ProviderException {
        try {
            return generateSelfSignedCertificate(keyPair.getPrivate(), keyPair.getPublic())
                    .getEncoded();
        } catch (IOException | CertificateParsingException e) {
            throw new ProviderException("Failed to generate self-signed certificate", e);
        } catch (CertificateEncodingException e) {
            throw new ProviderException(
                    "Failed to obtain encoded form of self-signed certificate", e);
        }
    }

    private byte[] getRealKeyBlobByKeyName(String keyName) {
        Log.d(SoterUtil.TAG, "getRealKeyBlobByKeyName: keyName = " + keyName);

        return mKeyStore.get(Credentials.USER_PRIVATE_KEY + keyName);
    }

    @SuppressWarnings("deprecation")
    private X509Certificate generateSelfSignedCertificateWithValidSignature(
            PrivateKey privateKey, PublicKey publicKey, String signatureAlgorithm)
                    throws Exception {
        final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setPublicKey(publicKey);
        certGen.setSerialNumber(mSpec.getCertificateSerialNumber());
        certGen.setSubjectDN(mSpec.getCertificateSubject());
        certGen.setIssuerDN(mSpec.getCertificateSubject());
        certGen.setNotBefore(mSpec.getCertificateNotBefore());
        certGen.setNotAfter(mSpec.getCertificateNotAfter());
        certGen.setSignatureAlgorithm(signatureAlgorithm);
        return certGen.generate(privateKey);
    }

    @SuppressWarnings("deprecation")
    private X509Certificate generateSelfSignedCertificateWithFakeSignature(
            PublicKey publicKey) throws IOException, CertificateParsingException {
        V3TBSCertificateGenerator tbsGenerator = new V3TBSCertificateGenerator();
        ASN1ObjectIdentifier sigAlgOid;
        AlgorithmIdentifier sigAlgId;
        byte[] signature;
        switch (mKeymasterAlgorithm) {
            case KeymasterDefs.KM_ALGORITHM_EC:
                sigAlgOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
                sigAlgId = new AlgorithmIdentifier(sigAlgOid);
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(new DERInteger(0));
                v.add(new DERInteger(0));
                signature = new DERSequence().getEncoded();
                break;
            case KeymasterDefs.KM_ALGORITHM_RSA:
                sigAlgOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
                sigAlgId = new AlgorithmIdentifier(sigAlgOid, DERNull.INSTANCE);
                signature = new byte[1];
                break;
            default:
                throw new ProviderException("Unsupported key algorithm: " + mKeymasterAlgorithm);
        }

        try (ASN1InputStream publicKeyInfoIn = new ASN1InputStream(publicKey.getEncoded())) {
            tbsGenerator.setSubjectPublicKeyInfo(
                    SubjectPublicKeyInfo.getInstance(publicKeyInfoIn.readObject()));
        }
        tbsGenerator.setSerialNumber(new ASN1Integer(mSpec.getCertificateSerialNumber()));
        X509Principal subject =
                new X509Principal(mSpec.getCertificateSubject().getEncoded());
        tbsGenerator.setSubject(subject);
        tbsGenerator.setIssuer(subject);
        tbsGenerator.setStartDate(new Time(mSpec.getCertificateNotBefore()));
        tbsGenerator.setEndDate(new Time(mSpec.getCertificateNotAfter()));
        tbsGenerator.setSignature(sigAlgId);
        TBSCertificate tbsCertificate = tbsGenerator.generateTBSCertificate();

        ASN1EncodableVector result = new ASN1EncodableVector();
        result.add(tbsCertificate);
        result.add(sigAlgId);
        result.add(new DERBitString(signature));
        return new X509CertificateObject(Certificate.getInstance(new DERSequence(result)));
    }

    private static int getDefaultKeySize(int keymasterAlgorithm) {
        return RSA_DEFAULT_KEY_SIZE;
    }

    private static void checkValidKeySize(int keymasterAlgorithm, int keySize)
            throws InvalidAlgorithmParameterException {
        if (keySize < RSA_MIN_KEY_SIZE || keySize > RSA_MAX_KEY_SIZE) {
            throw new InvalidAlgorithmParameterException("RSA key size must be >= "
                    + RSA_MIN_KEY_SIZE + " and <= " + RSA_MAX_KEY_SIZE);
        }
    }

    /**
     * Returns the {@code Signature} algorithm to be used for signing a certificate using the
     * specified key or {@code null} if the key cannot be used for signing a certificate.
     */
    @Nullable
    private static String getCertificateSignatureAlgorithm(
            int keymasterAlgorithm,
            int keySizeBits,
            KeyGenParameterSpec spec) {
        // Constraints:
        // 1. Key must be authorized for signing without user authentication.
        // 2. Signature digest must be one of key's authorized digests.
        // 3. For RSA keys, the digest output size must not exceed modulus size minus space overhead
        //    of RSA PKCS#1 signature padding scheme (about 30 bytes).
        // 4. For EC keys, the there is no point in using a digest whose output size is longer than
        //    key/field size because the digest will be truncated to that size.

        if ((spec.getPurposes() & KeyProperties.PURPOSE_SIGN) == 0) {
            // Key not authorized for signing
            return null;
        }
        if (spec.isUserAuthenticationRequired()) {
            // Key not authorized for use without user authentication
            return null;
        }
        if (!spec.isDigestsSpecified()) {
            // Key not authorized for any digests -- can't sign
            return null;
        }
        // Check whether this key is authorized for PKCS#1 signature padding.
        // We use Bouncy Castle to generate self-signed RSA certificates. Bouncy Castle
        // only supports RSA certificates signed using PKCS#1 padding scheme. The key needs
        // to be authorized for PKCS#1 padding or padding NONE which means any padding.
        boolean pkcs1SignaturePaddingSupported =
                com.android.internal.util.ArrayUtils.contains(
                        KeyProperties.SignaturePadding.allToKeymaster(
                                spec.getSignaturePaddings()),
                        KeymasterDefs.KM_PAD_RSA_PKCS1_1_5_SIGN);
        if (!pkcs1SignaturePaddingSupported) {
            // Key not authorized for PKCS#1 signature padding -- can't sign
            return null;
        }

        Set<Integer> availableKeymasterDigests = getAvailableKeymasterSignatureDigests(
                spec.getDigests(),
                AndroidKeyStoreBCWorkaroundProvider.getSupportedEcdsaSignatureDigests());

        // The amount of space available for the digest is less than modulus size by about
        // 30 bytes because padding must be at least 11 bytes long (00 || 01 || PS || 00,
        // where PS must be at least 8 bytes long), and then there's also the 15--19 bytes
        // overhead (depending the on chosen digest) for encoding digest OID and digest
        // value in DER.
        int maxDigestOutputSizeBits = keySizeBits - 30 * 8;
        int bestKeymasterDigest = -1;
        int bestDigestOutputSizeBits = -1;
        for (int keymasterDigest : availableKeymasterDigests) {
            int outputSizeBits = KeymasterUtils.getDigestOutputSizeBits(keymasterDigest);
            if (outputSizeBits > maxDigestOutputSizeBits) {
                // Digest too long (signature generation will fail) -- skip
                continue;
            }
            if (bestKeymasterDigest == -1) {
                // First digest tested -- definitely the best so far
                bestKeymasterDigest = keymasterDigest;
                bestDigestOutputSizeBits = outputSizeBits;
            } else {
                // The longer the better
                if (outputSizeBits > bestDigestOutputSizeBits) {
                    bestKeymasterDigest = keymasterDigest;
                    bestDigestOutputSizeBits = outputSizeBits;
                }
            }
        }
        if (bestKeymasterDigest == -1) {
            return null;
        }
        return KeyProperties.Digest.fromKeymasterToSignatureAlgorithmDigest(
                bestKeymasterDigest) + "WithRSA";
    }

    private static String[] getSupportedEcdsaSignatureDigests() {
        return new String[] {"NONE", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"};
    }

    private static Set<Integer> getAvailableKeymasterSignatureDigests(
            @KeyProperties.DigestEnum String[] authorizedKeyDigests,
            @KeyProperties.DigestEnum String[] supportedSignatureDigests) {
        Set<Integer> authorizedKeymasterKeyDigests = new HashSet<Integer>();
        for (int keymasterDigest : KeyProperties.Digest.allToKeymaster(authorizedKeyDigests)) {
            authorizedKeymasterKeyDigests.add(keymasterDigest);
        }
        Set<Integer> supportedKeymasterSignatureDigests = new HashSet<Integer>();
        for (int keymasterDigest
             : KeyProperties.Digest.allToKeymaster(supportedSignatureDigests)) {
            supportedKeymasterSignatureDigests.add(keymasterDigest);
        }
        Set<Integer> result = new HashSet<Integer>(supportedKeymasterSignatureDigests);
        result.retainAll(authorizedKeymasterKeyDigests);
        return result;
    }

    private void generateKeystoreKeyPair(final String privateKeyAlias, KeymasterArguments args,
            byte[] additionalEntropy, final int flags) throws ProviderException {
        KeyCharacteristics resultingKeyCharacteristics = new KeyCharacteristics();
        int errorCode = mKeyStore.generateKey(privateKeyAlias, args, additionalEntropy,
                flags, resultingKeyCharacteristics);
        if (errorCode != KeyStore.NO_ERROR) {
            throw new ProviderException(
                    "Failed to generate key pair", KeyStore.getKeyStoreException(errorCode));
        }
    }

    private KeymasterArguments constructKeyGenerationArguments() {
        KeymasterArguments args = new KeymasterArguments();
        args.addUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, mKeySizeBits);
        args.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, mKeymasterAlgorithm);
        args.addEnums(KeymasterDefs.KM_TAG_PURPOSE, mKeymasterPurposes);
        args.addEnums(KeymasterDefs.KM_TAG_BLOCK_MODE, mKeymasterBlockModes);
        args.addEnums(KeymasterDefs.KM_TAG_PADDING, mKeymasterEncryptionPaddings);
        args.addEnums(KeymasterDefs.KM_TAG_PADDING, mKeymasterSignaturePaddings);
        args.addEnums(KeymasterDefs.KM_TAG_DIGEST, mKeymasterDigests);

        KeymasterUtils.addUserAuthArgs(args,
                mSpec.isUserAuthenticationRequired(),
                mSpec.getUserAuthenticationValidityDurationSeconds(),
                false,
                true);
        args.addDateIfNotNull(KeymasterDefs.KM_TAG_ACTIVE_DATETIME, mSpec.getKeyValidityStart());
        args.addDateIfNotNull(KeymasterDefs.KM_TAG_ORIGINATION_EXPIRE_DATETIME,
                mSpec.getKeyValidityForOriginationEnd());
        args.addDateIfNotNull(KeymasterDefs.KM_TAG_USAGE_EXPIRE_DATETIME,
                mSpec.getKeyValidityForConsumptionEnd());
        addAlgorithmSpecificParameters(args);

        return args;
    }

    private KeyPair loadKeystoreKeyPair(final String privateKeyAlias) throws ProviderException {
        try {
            KeyPair result  = SoterKeyStoreProvider.loadAndroidKeyStoreKeyPairFromKeystore(
                    mKeyStore, privateKeyAlias);
            if (!mJcaKeyAlgorithm.equalsIgnoreCase(result.getPrivate().getAlgorithm())) {
                throw new ProviderException(
                        "Generated key pair algorithm does not match requested algorithm: "
                                + result.getPrivate().getAlgorithm() + " vs " + mJcaKeyAlgorithm);
            }
            return result;
        } catch (UnrecoverableKeyException e) {
            throw new ProviderException("Failed to load generated key pair from keystore", e);
        }
    }

    private void storeCertificate(String prefix, byte[] certificateBytes, final int flags,
            String failureMessage) throws ProviderException {
        int insertErrorCode = mKeyStore.insert(
                prefix + mEntryAlias,
                certificateBytes,
                KeyStore.UID_SELF,
                flags);
        if (insertErrorCode != KeyStore.NO_ERROR) {
            throw new ProviderException(failureMessage,
                    KeyStore.getKeyStoreException(insertErrorCode));
        }
    }
}
