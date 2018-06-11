package itsp03;
/*
 * Decompiled with CFR 0_123.
 */


import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class RSFTestJava8 {
    public final String SIGNATURE_PARAMETERS = "SHA512withRSA";
    public final String CIPHER_PARAMETERS = "AES/CTR/NoPadding";
    public static String privFileName;
    public static String pubFileName;
    public static String ssfFileName;
    public static String docFileName;
    private PrivateKey privKey = null;
    private PublicKey pubKey = null;
    public byte[] encodedSKey = null;
    public byte[] encryptedSKey = null;
    private byte[] signature = null;

    public static void main(String[] paramArrayOfString) {
        if (paramArrayOfString.length < 4) {
            System.out.println("Usage: java RSFTestJava8 filename.prv filename.pub ssf-filename doc-filename");
            System.exit(0);
        } else {
            RSFTestJava8 localRSFTestJava8 = new RSFTestJava8();
            privFileName = paramArrayOfString[0];
            pubFileName = paramArrayOfString[1];
            ssfFileName = paramArrayOfString[2];
            docFileName = paramArrayOfString[3];
            System.out.println("RSFTestJava8 startet mit folgenden Argumenten:");
            System.out.println("--------------- PrivateKey-File: " + privFileName);
            System.out.println("--------------- PublicKey-File:  " + pubFileName);
            System.out.println("--------------- Chipher-File:    " + ssfFileName);
            System.out.println("--------------- Plaintext-File:  " + docFileName);
            localRSFTestJava8.readPrivKey();
            localRSFTestJava8.readPubKey();
            localRSFTestJava8.convertSSFFile();
            if (localRSFTestJava8.verifySignature()) {
                System.out.println("\n\n:-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) ");
                System.out.println("Alles fertig, wenn die Datei korrekt entschluesselt wurde. Schon mal herzlichen Glueckwunsch!");
                System.out.println(":-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) :-) ");
            } else {
                System.out.println("RSFTestJava8: Hat leider noch nicht geklappt, schade ... :-(");
            }
        }
    }

    public void readPrivKey() {
        byte[] arrayOfByte1 = null;
        byte[] arrayOfByte2 = null;
        try {
            DataInputStream localDataInputStream = new DataInputStream(new FileInputStream(privFileName));
            int i = localDataInputStream.readInt();
            arrayOfByte2 = new byte[i];
            localDataInputStream.read(arrayOfByte2);
            i = localDataInputStream.readInt();
            arrayOfByte1 = new byte[i];
            localDataInputStream.read(arrayOfByte1);
            localDataInputStream.close();
        }
        catch (IOException localIOException) {
            this.Error("Fehler beim Lesen des private keys!", localIOException);
        }
        KeyFactory localKeyFactory = null;
        try {
            localKeyFactory = KeyFactory.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
            this.Error("Es existiert keine KeyFactory fuer RSA.", localNoSuchAlgorithmException);
        }
        PKCS8EncodedKeySpec localPKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(arrayOfByte1);
        try {
            this.privKey = localKeyFactory.generatePrivate(localPKCS8EncodedKeySpec);
        }
        catch (InvalidKeySpecException localInvalidKeySpecException) {
            this.Error("Fehler beim Konvertieren des Schluessels.", localInvalidKeySpecException);
        }
        String str = new String(arrayOfByte2);
        System.out.println("\nPrivate key fuer <" + str + "> wurde erfolgreich gelesen: " + this.byteArraytoHexString(arrayOfByte1));
    }

    public void readPubKey() {
        byte[] arrayOfByte1 = null;
        byte[] arrayOfByte2 = null;
        try {
            DataInputStream localDataInputStream = new DataInputStream(new FileInputStream(pubFileName));
            int i = localDataInputStream.readInt();
            arrayOfByte2 = new byte[i];
            localDataInputStream.read(arrayOfByte2);
            i = localDataInputStream.readInt();
            arrayOfByte1 = new byte[i];
            localDataInputStream.read(arrayOfByte1);
            localDataInputStream.close();
        }
        catch (IOException localIOException) {
            this.Error("Fehler beim Lesen des public keys!", localIOException);
        }
        KeyFactory localKeyFactory = null;
        try {
            localKeyFactory = KeyFactory.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
            this.Error("Es existiert keine KeyFactory fuer RSA.", localNoSuchAlgorithmException);
        }
        X509EncodedKeySpec localX509EncodedKeySpec = new X509EncodedKeySpec(arrayOfByte1);
        try {
            this.pubKey = localKeyFactory.generatePublic(localX509EncodedKeySpec);
        }
        catch (InvalidKeySpecException localInvalidKeySpecException) {
            this.Error("Fehler beim Konvertieren des Schluessels.", localInvalidKeySpecException);
        }
        String str = new String(arrayOfByte2);
        System.out.println("\nPublic key fuer <" + str + "> wurde erfolgreich gelesen: " + this.byteArraytoHexString(arrayOfByte1));
    }

    public void convertSSFFile() {
        try {
            DataInputStream localDataInputStream = new DataInputStream(new FileInputStream(ssfFileName));
            int i = localDataInputStream.readInt();
            this.encryptedSKey = new byte[i];
            localDataInputStream.read(this.encryptedSKey);
            System.out.println("\nDer geheime Schluessel wurde erfolgreich gelesen!");
            i = localDataInputStream.readInt();
            this.signature = new byte[i];
            localDataInputStream.read(this.signature);
            System.out.println("Die Signatur des geheimen Schl\u00fcssels wurde erfolgreich gelesen!");
            i = localDataInputStream.readInt();
            byte[] arrayOfByte1 = new byte[i];
            localDataInputStream.read(arrayOfByte1);
            System.out.println("Die algorithmischen Parameter des geheimen Schl\u00fcssels wurden erfolgreich gelesen!");
            AlgorithmParameters localAlgorithmParameters = AlgorithmParameters.getInstance("AES");
            localAlgorithmParameters.init(arrayOfByte1);
            System.out.println("Die algorithmischen Parameter des geheimen Schl\u00fcssels wurden erfolgreich initialisiert!");
            this.decryptKey();
            System.out.println("Der geheime Schluessel: " + this.byteArraytoHexString(this.encodedSKey) + " wurde erfolgreich entschluesselt!");
            Cipher localCipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec localSecretKeySpec = new SecretKeySpec(this.encodedSKey, "AES");
            localCipher.init(2, (Key)localSecretKeySpec, localAlgorithmParameters);
            System.out.println("Das Cipher-Objekt  wurde erfolgreich initialisiert!");
            FileOutputStream localFileOutputStream = new FileOutputStream(docFileName);
            byte[] arrayOfByte2 = new byte[1024];
            while ((i = localDataInputStream.read(arrayOfByte2)) > 0) {
                localFileOutputStream.write(localCipher.update(arrayOfByte2, 0, i));
            }
            localFileOutputStream.write(localCipher.doFinal());
            localDataInputStream.close();
            localFileOutputStream.close();
        }
        catch (Exception localException) {
            this.Error("Fehler beim Schreiben der Dokumentendatei oder Lesen der .ssf-Datei!", localException);
        }
    }

    public void decryptKey() {
        try {
            Cipher localCipher = Cipher.getInstance("RSA");
            localCipher.init(2, this.privKey);
            this.encodedSKey = localCipher.doFinal(this.encryptedSKey);
        }
        catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
            this.Error("Keine Implementierung fuer RSA vorhanden!", localNoSuchAlgorithmException);
        }
        catch (InvalidKeyException localInvalidKeyException) {
            this.Error("Falscher Algorithmus?", localInvalidKeyException);
        }
        catch (Exception localException) {
            this.Error("Fehler bei der Entschluesselung des geheimen Schluessels", localException);
        }
    }

    public boolean verifySignature() {
        boolean bool = false;
        Signature localSignature = null;
        try {
            localSignature = Signature.getInstance("SHA512withRSA");
            localSignature.initVerify(this.pubKey);
            localSignature.update(this.encodedSKey);
        }
        catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
            this.Error("Keine Implementierung fuer SHA512withRSA vorhanden!", localNoSuchAlgorithmException);
        }
        catch (SignatureException localSignatureException1) {
            this.Error("Fehler beim Ueberpruefen der Signatur!", localSignatureException1);
        }
        catch (InvalidKeyException localInvalidKeyException) {
            this.Error("Falscher Schluesseltyp bei Ueberpruefung der Signatur!", localInvalidKeyException);
        }
        try {
            bool = localSignature.verify(this.signature);
            if (bool) {
                System.out.println("\nDie Signatur wurde erfolgreich verifiziert: " + this.byteArraytoHexString(this.signature));
            } else {
                System.out.println("\nDie Signatur " + this.byteArraytoHexString(this.signature) + " konnte nicht verifiziert werden!!!\n");
            }
        }
        catch (SignatureException localSignatureException2) {
            this.Error("Fehler beim Verifizieren der Signatur!", localSignatureException2);
        }
        return bool;
    }

    private String byteArraytoHexString(byte[] paramArrayOfByte) {
        String str = "";
        int i = 0;
        while (i < paramArrayOfByte.length) {
            str = String.valueOf(str) + this.bytetoHexString(paramArrayOfByte[i]) + " ";
            ++i;
        }
        return str;
    }

    private String bytetoHexString(byte paramByte) {
        String str = Integer.toHexString(paramByte & 255).toUpperCase();
        str = String.valueOf(str.length() < 2 ? "0" : "") + str;
        return str;
    }

    private void Error(String paramString, Exception paramException) {
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        System.out.println(paramString);
        System.out.println(paramException.getMessage());
        System.out.println("Hat leider noch nicht geklappt --> Abbruch der Verarbeitung, sorry!");
        System.exit(0);
    }
}