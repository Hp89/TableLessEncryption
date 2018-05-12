/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package TablelessEncrypt;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Vector;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;
import javafx.scene.input.KeyCode;

/**
 *
 * @author harre
 */
public class TablelessEncrypt {

    /**
     * @param args the command line arguments
     */
    static AsymmetricCryptography ac;
    static Random r = new Random();
    static int uran=0,s4 = 0;
    public static void main(String args[]) throws Exception {
        String a = "apple";
        //a.hashCode();

        GenerateKeys gk;
        ac = new AsymmetricCryptography();
        try {
            gk = new GenerateKeys(1024);
            gk.createKeys();
            gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
            gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.println(e.getMessage());
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }

        HashMap H = new HashMap<Integer, String>();

        PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey");
        PublicKey publicKey = ac.getPublic("KeyPair/publicKey");
        Scanner s = new Scanner(System.in);
        System.out.println("Enter any sentence");
        String msg = s.next();

        int rc = r.nextInt(100);
        uran = rc;
        String nmsg = msg +","+ rc;
        String encrypted_msg = ac.encryptText(nmsg, privateKey);

        /*System.out.println("Original Message: " + msg
                + "\nEncrypted Message: " + encrypted_msg
                + "\nDecrypted Message: " + decrypted_msg);
         */
        int uid = 1;
        H.put(uid, encrypted_msg);
        server(uid,publicKey,encrypted_msg);


        /* if (new File("KeyPair/text.txt").exists()) {
            ac.encryptFile(ac.getFileInBytes(new File("KeyPair/text.txt")),
                    new File("KeyPair/text_encrypted.txt"), privateKey);
            ac.decryptFile(ac.getFileInBytes(new File("KeyPair/text_encrypted.txt")),
                    new File("KeyPair/text_decrypted.txt"), publicKey);
        } else {
            System.out.println("Create a file text.txt under folder KeyPair");
         */
    }

    public static HashMap createdb(){
        HashMap db = new HashMap<Integer,String>();
        db.put("apple".hashCode(),"apple");
        return db;
    }
    public static void User(int x,int n) throws Exception{
        int u3n = x ^ uran;
        System.out.println("u3n"+u3n);
        int n3ha = Integer.hashCode(u3n);
        System.out.println("n3ha"+n3ha);
        if(n3ha!=n){
            System.out.println("Failure");
            System.exit(n3ha);
        }
        else{
            int s4ss = Integer.hashCode(uran+u3n);
            System.out.println("s4ss"+s4ss);
            server(s4ss);
        }
    }
    public static void server(int a){
        if (a == s4)
            System.out.println("Accepted");
        else
            System.out.println("Sorry You are rejected");
    }
    public void check(){
        System.out.println("Working");
    }
    public static void server(int uid,PublicKey p,String encp) throws Exception{
        String decrypted_message = ac.decryptText(encp,p);int rs = 0;
        System.out.println(decrypted_message);
        int commp = decrypted_message.indexOf(",");
        String pwi = decrypted_message.substring(0, commp);
        System.out.println(pwi);
        int rci = Integer.parseInt(decrypted_message.substring(commp+1,decrypted_message.length()));
        int hpwi = pwi.hashCode();
        HashMap h = new HashMap<Integer,String>();
        h = createdb();
        if(!h.containsKey(hpwi)){
            System.out.println("Failure");
            System.exit(hpwi);
        }
        else{
            rs = r.nextInt();
            int xor1 = rs ^ rci;
            int nhc = Integer.hashCode(rs);
            User(xor1,nhc);

        }
        s4 = Integer.hashCode(rci+rs);
        System.out.println("s4"+s4);


    }

}


class AsymmetricCryptography {

    public Cipher cipher;

    public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance("RSA");
    }
    //https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html

    public PrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    //https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html

    public PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public void encryptFile(byte[] input, File output, PrivateKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    public void decryptFile(byte[] input, File output, PublicKey key) throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    public void writeToFile(File output, byte[] toWrite) throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    public String encryptText(String msg, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    public String decryptText(String msg, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
    }

    public byte[] getFileInBytes(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }

}

class GenerateKeys {

    public KeyPairGenerator keyGen;
    public KeyPair pair;
    public PrivateKey privateKey;
    public PublicKey publicKey;

    public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);
    }

    public void createKeys() {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

}

