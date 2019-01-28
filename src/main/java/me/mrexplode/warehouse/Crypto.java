package me.mrexplode.warehouse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * Credits to erickson and wufoo, from stackoverflow. I was too lazy to do this
 */
public class Crypto {

    String mPassword = null;
    public final static int SALT_LEN = 8;
    byte[] mInitVec = null;
    byte[] mSalt = null;
    Cipher mEcipher = null;
    Cipher mDecipher = null;
    private final int KEYLEN_BITS = 128; // see notes below where this is used.
    private final int ITERATIONS = 65536;
    private final int MAX_FILE_BUF = 1024;

    /**
     * create an object with just the passphrase from the user. Don't do anything
     * else yet
     * 
     * @param password
     */
    public Crypto(String hash) {
        mPassword = hash;
    }

    /**
     * return the generated salt for this object
     * 
     * @return salt
     */
    public byte[] getSalt() {
        return (mSalt);
    }

    /**
     * return the initialization vector created from setupEncryption
     * 
     * @return initvector
     */
    public byte[] getInitVec() {
        return (mInitVec);
    }

    /**
     * debug/print messages
     * 
     * @param msg
     */
    private static void debug(String msg) {
        System.out.println("** Crypt ** " + msg);
    }
    
    public static Cipher getOneTimeCipher(int mode, String password) {
        try {
            Cipher c = Cipher.getInstance("PBEWithMD5AndDES");
            final Random random = new Random(43287234L);
            final byte[] array = new byte[8];
            random.nextBytes(array);
            c.init(mode, SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(new PBEKeySpec(password.toCharArray())), new PBEParameterSpec(array, 5));
            return c;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * this must be called after creating the initial Crypto object. It creates a
     * salt of SALT_LEN bytes and generates the salt bytes using secureRandom(). The
     * encryption secret key is created along with the initialization vectory. The
     * member variable mEcipher is created to be used by the class later on when
     * either creating a CipherOutputStream, or encrypting a buffer to be written to
     * disk.
     * 
     * @throws GeneralSecurityException
     */
    public void setupEncrypt() throws GeneralSecurityException {
        SecretKeyFactory factory = null;
        SecretKey tmp = null;

        // crate secureRandom salt and store as member var for later use
        mSalt = new byte[SALT_LEN];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(mSalt);
        debug("generated salt :" + Hex.encodeHexString(mSalt));

        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        /*
         * Derive the key, given password and salt.
         * 
         * in order to do 256 bit crypto, you have to muck with the files for Java's
         * "unlimted security" The end user must also install them (not compiled in) so
         * beware. see here:
         * http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
         */
        KeySpec spec = new PBEKeySpec(mPassword.toCharArray(), mSalt, ITERATIONS, KEYLEN_BITS);
        tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        /*
         * Create the Encryption cipher object and store as a member variable
         */
        mEcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        mEcipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = mEcipher.getParameters();

        // get the initialization vectory and store as member var
        mInitVec = params.getParameterSpec(IvParameterSpec.class).getIV();

        debug("mInitVec is :" + Hex.encodeHexString(mInitVec));
    }

    /**
     * If a file is being decrypted, we need to know the pasword, the salt and the
     * initialization vector (iv). We have the password from initializing the class.
     * pass the iv and salt here which is obtained when encrypting the file
     * initially.
     * 
     * @param initvec
     * @param salt
     * @throws GeneralSecurityException
     * @throws DecoderException
     */
    public void setupDecrypt(String initvec, String salt) throws GeneralSecurityException, DecoderException {
        SecretKeyFactory factory = null;
        SecretKey tmp = null;
        SecretKey secret = null;

        // since we pass it as a string of input, convert to a actual byte buffer here
        mSalt = Hex.decodeHex(salt.toCharArray());
        debug("got salt " + Hex.encodeHexString(mSalt));

        // get initialization vector from passed string
        mInitVec = Hex.decodeHex(initvec.toCharArray());
        debug("got initvector: " + Hex.encodeHexString(mInitVec));

        /* Derive the key, given password and salt. */
        // in order to do 256 bit crypto, you have to muck with the files for Java's
        // "unlimted security"
        // The end user must also install them (not compiled in) so beware.
        // see here:
        // http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(mPassword.toCharArray(), mSalt, ITERATIONS, KEYLEN_BITS);

        tmp = factory.generateSecret(spec);
        secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        /* Decrypt the message, given derived key and initialization vector. */
        mDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        mDecipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(mInitVec));
    }

    /**
     * This is where we write out the actual encrypted data to disk using the Cipher
     * created in setupEncrypt(). Pass two file objects representing the actual
     * input (cleartext) and output file to be encrypted.
     * 
     * there may be a way to write a cleartext header to the encrypted file
     * containing the salt, but I ran into uncertain problems with that.
     * 
     * @param input  - the cleartext file to be encrypted
     * @param output - the encrypted data file
     * @throws IOException 
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void writeEncryptedFile(File input, File output) throws IOException, GeneralSecurityException {
        FileInputStream fin;
        FileOutputStream fout;
        long totalread = 0;
        long start = System.currentTimeMillis();
        int nread = 0;
        byte[] inbuf = new byte[MAX_FILE_BUF];

        fout = new FileOutputStream(output);
        fin = new FileInputStream(input);

        while ((nread = fin.read(inbuf)) > 0) {
            //debug("read " + nread + " bytes");
            totalread += nread;

            // create a buffer to write with the exact number of bytes read. Otherwise a
            // short read fills inbuf with 0x0
            // and results in full blocks of MAX_FILE_BUF being written.
            byte[] trimbuf = new byte[nread];
            for (int i = 0; i < nread; i++)
                trimbuf[i] = inbuf[i];

            // encrypt the buffer using the cipher obtained previosly
            byte[] tmp = mEcipher.update(trimbuf);

            // I don't think this should happen, but just in case..
            if (tmp != null)
                fout.write(tmp);
        }

        // finalize the encryption since we've done it in blocks of MAX_FILE_BUF
        byte[] finalbuf = mEcipher.doFinal();
        if (finalbuf != null)
            fout.write(finalbuf);

        fout.flush();
        fin.close();
        fout.close();

        debug("wrote " + totalread + " encrypted bytes, in " + (System.currentTimeMillis() - start) + " ms");
    }

    /**
     * Read from the encrypted file (input) and turn the cipher back into cleartext.
     * Write the cleartext buffer back out to disk as (output) File.
     * 
     * I left CipherInputStream in here as a test to see if I could mix it with the
     * update() and final() methods of encrypting and still have a correctly
     * decrypted file in the end. Seems to work so left it in.
     * 
     * @param input  - File object representing encrypted data on disk
     * @param output - File object of cleartext data to write out after decrypting
     * @throws IOException 
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public void readEncryptedFile(File input, File output) throws IOException {
        FileInputStream fin;
        FileOutputStream fout;
        CipherInputStream cin;
        long totalread = 0;
        long start = System.currentTimeMillis();
        int nread = 0;
        byte[] inbuf = new byte[MAX_FILE_BUF];

        fout = new FileOutputStream(output);
        fin = new FileInputStream(input);

        // creating a decoding stream from the FileInputStream above using the cipher
        // created from setupDecrypt()
        cin = new CipherInputStream(fin, mDecipher);

        while ((nread = cin.read(inbuf)) > 0) {
            //debug("read " + nread + " bytes");
            totalread += nread;

            // create a buffer to write with the exact number of bytes read. Otherwise a
            // short read fills inbuf with 0x0
            byte[] trimbuf = new byte[nread];
            for (int i = 0; i < nread; i++)
                trimbuf[i] = inbuf[i];

            // write out the size-adjusted buffer
            fout.write(trimbuf);
        }

        fout.flush();
        cin.close();
        fin.close();
        fout.close();

        debug("wrote " + totalread + " encrypted bytes, in " + (System.currentTimeMillis() - start) + " ms");
    }
    
    public String encryptString(String original) {
        try {
            byte[] enc = mEcipher.doFinal(original.getBytes(Charset.forName("UTF-8")));
            return Hex.encodeHexString(enc);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public String decryptString(String encrypted) {
        try {
            String decryptedString = new String(mDecipher.doFinal(Hex.decodeHex(encrypted.toCharArray())));
            return decryptedString;
        } catch (GeneralSecurityException | DecoderException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * adding main() for usage demonstration. With member vars, some of the locals
     * would not be needed
     */
    public static void main0(String[] args) {

        // create the input.txt file in the current directory before continuing
        File input = new File("D:\\pjano\\Documents\\Eclipse\\pjWorkspace\\imageWarehouse\\test.jpg");
        File eoutput = new File("encrypted.JPG");
        File doutput = new File("decrypted.JPG");
        String iv = null;
        String salt = null;
        Crypto en = new Crypto("mypassword");

        /*
         * setup encryption cipher using password. print out iv and salt
         */
        try {
            en.setupEncrypt();
        } catch (GeneralSecurityException e1) {
            e1.printStackTrace();
        }
        iv = Hex.encodeHexString(en.getInitVec()).toUpperCase();
        salt = Hex.encodeHexString(en.getSalt()).toUpperCase();

        /*
         * write out encrypted file
         */
        try {
            en.writeEncryptedFile(input, eoutput);
        } catch (IOException e2) {
            e2.printStackTrace();
        } catch (GeneralSecurityException e2) {
            e2.printStackTrace();
        }
        System.out.printf("File encrypted to " + eoutput.getName() + "\niv:" + iv + "\nsalt:" + salt + "\n\n");

        /*
         * decrypt file
         */
        Crypto dc = new Crypto("mypassword");
        try {
            dc.setupDecrypt(iv, salt);
        } catch (GeneralSecurityException e1) {
            e1.printStackTrace();
        } catch (DecoderException e1) {
            e1.printStackTrace();
        }

        /*
         * write out decrypted file
         */
        try {
            dc.readEncryptedFile(eoutput, doutput);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("decryption finished to " + doutput.getName());
    }

}
