package me.mrexplode.warehouse;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.swing.JProgressBar;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Warehouse {
    
    private File storeDir;
    private File mapFile;
    private String password;
    private String passwordHash;
    private Crypto crypto;
    
    //mutlithread things
    protected Executor executor;
    protected InverseSemaphore semaphore;
    
    public Warehouse(File storeDir, String password) {
        this.storeDir = storeDir;
        this.mapFile = new File(storeDir, "25142d025c0a10143eb9f2298fb46f68");
        this.password = password;
        this.passwordHash = hash(password);
        this.crypto = new Crypto(this.passwordHash);
        
        this.executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        this.semaphore = new InverseSemaphore();
    }
    
    /**
     * 
     * @return true when the warehouse was initialized with correct pwd, or the map file doesn't exist
     */
    public boolean checkPassword() {
        System.out.println("Checking passwords...");
        if (!mapFile.exists()) {return true;}
        //I hate this kind of try block, but this is useful now
        try (DataInputStream dIn = getIn(mapFile)) {
            return checkHash(password, dIn.readUTF());
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean unlock() {
        System.out.println("=== Unlocking " + storeDir.getName());
        long start = System.currentTimeMillis();
        try {
            if (!mapFile.exists()) return false;
            
            DataInputStream dataIn = getIn(mapFile);
            dataIn.readUTF();
            String salt = dataIn.readUTF();
            String iv = dataIn.readUTF();
            dataIn.close();
            
            crypto.setupDecrypt(iv, salt);

            semaphore.beforeSubmit();
            executor.execute(new CryptoWalker(storeDir, this, crypto, false));
            semaphore.awaitCompletion();

            mapFile.delete();
            
            System.out.println("=== Unlocked '" + storeDir.getName() + "' folder in " + (System.currentTimeMillis() - start) + " ms");
            return true;
        } catch (IOException | GeneralSecurityException | InterruptedException | DecoderException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean lock() {
        System.out.println("=== Locking " + storeDir.getName());
        long start = System.currentTimeMillis();
        try {
            crypto.setupEncrypt();
            
            DataOutputStream dataOut = getOut(mapFile);
            dataOut.writeUTF(passwordHash);
            dataOut.writeUTF(Hex.encodeHexString(crypto.getSalt()));
            dataOut.writeUTF(Hex.encodeHexString(crypto.getInitVec()));
            dataOut.close();
            
            semaphore.beforeSubmit();
            executor.execute(new CryptoWalker(storeDir, this, crypto, true));
            semaphore.awaitCompletion();
            
            System.out.println("=== Locked '" + storeDir.getName() + "' folder in " + (System.currentTimeMillis() - start) + " ms");
            return true;
        } catch (GeneralSecurityException | IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    @SuppressWarnings("resource")
    private static DataInputStream getIn(File f) throws FileNotFoundException {
        //this is ridiculous
        return new DataInputStream(new CipherInputStream(new FileInputStream(f), Crypto.getOneTimeCipher(Cipher.DECRYPT_MODE, "c2fc2f64438b1eb36b7e244bdb7bd535")));
    }
    
    @SuppressWarnings("resource")
    private static DataOutputStream getOut(File f) throws FileNotFoundException {
        //this is ridiculous
        return new DataOutputStream(new CipherOutputStream(new FileOutputStream(f, true), Crypto.getOneTimeCipher(Cipher.ENCRYPT_MODE, "c2fc2f64438b1eb36b7e244bdb7bd535")));
    }
    
    public static String hash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(password.getBytes(Charset.forName("UTF-8")));
            return Hex.encodeHexString(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static boolean checkHash(String password, String hash) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(password.getBytes(Charset.forName("UTF-8")));
            String pwdHash = Hex.encodeHexString(digest.digest());
            return hash.equals(pwdHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }
    
}
class CryptoWalker extends Thread {
    
    private File rootDir;
    private Warehouse parent;
    private Crypto cryptoModule;
    private boolean mode;
    
    /**
     * Constructs a CryptoWalker, with the specified mode.
     * 
     * @param root The root folder, where the walker starts
     * @param parent The warehouse object. we need the Executor and the InverseSemaphore from here
     * @param cryptoModule A NEW instance of Crypto class, to do crypthographic work
     * @param mode true for encode, false for decode
     */
    public CryptoWalker(File root, Warehouse parent, Crypto cryptoModule, boolean mode) {
        this.rootDir = root;
        if (root == null) {
            System.err.println("null root passed to constructor!");
        }
        this.parent = parent;
        this.cryptoModule = cryptoModule;
        this.mode = mode;
    }
    
    @Override
    public void run() {
        File[] files = rootDir.listFiles();
        if (files == null) {
            System.err.println("The file " + rootDir.getAbsolutePath() + " is not a directory.");
            parent.semaphore.taskCompleted();
            return;
        }
        
        System.out.println((mode ? "Encrypting" : "Decrypting") + " folder: " + rootDir.getName());
        for (File entry : files) {
            //we don't hurt our lock file
            if (entry.getName().equals("25142d025c0a10143eb9f2298fb46f68") && !entry.isDirectory())
                continue;
            
            if (entry.isDirectory()) {
                String dirName = "directory";
                if (mode) {
                    dirName = cryptoModule.encryptString(entry.getName());
                } else {
                    dirName = cryptoModule.decryptString(entry.getName());
                }
                entry.renameTo(new File(rootDir, dirName));
                
                Crypto cInstance = new Crypto(cryptoModule.mPassword, cryptoModule.getInitVec(), cryptoModule.getSalt(), cryptoModule.getEncryptCipher(), cryptoModule.getDecryptCipher());
                parent.semaphore.beforeSubmit();
                parent.executor.execute(new CryptoWalker(new File(rootDir, dirName), parent, cInstance, mode));
            } else {
                if (mode) {
                    //encrypt
                    try {
                        cryptoModule.writeEncryptedFile(entry, new File(rootDir, cryptoModule.encryptString(entry.getName())));
                        entry.delete();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }
                } else {
                    //decrypt
                    try {
                        cryptoModule.readEncryptedFile(entry, new File(rootDir, cryptoModule.decryptString(entry.getName())));
                        entry.delete();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        
        System.out.println("Finished " + (mode ? "encrypting " : "decrypting ") + rootDir.getName() + " folder");
        parent.semaphore.taskCompleted();
    }
    
}
