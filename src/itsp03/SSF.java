/**
 * 
 */
package itsp03;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * 
 *  Erzeugen, Signieren und Verschlüsseln eines geheimen Sitzungsschlüssels und Verschlüsseln
 *	einer Dokumentendatei (Sender) 
 *
 * @author Nelli Welker, Etienne Onasch
 *
 */
public class SSF {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		SSF ssf = new SSF();
//		System.out.println(ssf.readPubKey("Mueller.pub"));
//		System.out.println(ssf.readPrivKey("Mueller.prv"));
//		System.out.println(ssf.generateSecretKeyForAES());
//		try {
//			System.out.println("SIGN: "+ssf.generateSignature(ssf.readPrivKey("Mueller.prv")));
//		} catch (SignatureException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		System.out.println(ssf.encodeSecretKey(ssf.generateSecretKeyForAES(), ssf.readPubKey("Mueller.pub")));
		ssf.readAndEncryptData(args[0], args[1], args[2], args[3]);
	}
	
	public String getFileContent( File fis ) throws IOException {
	    return new String(Files.readAllBytes(Paths.get(fis.getPath())));
	}
	/**
	 * Liest einen privaten Schlüssel aus einer Datei ein.
	 * 
	 * @param file
	 * @return
	 */
	public PrivateKey readPrivKey(String file){
		PrivateKey privKey = null;
//		File filePriv = new File(file);
		KeyFactory kf;
		
		byte[] inhaberBytes = null;
		byte[] privKeyBytes = null;
		
		try {
			//Lesen des privaten RSA-Keys
			
			DataInputStream dis = new DataInputStream(new FileInputStream(file));
			//Länge des InhaberNamens
			int len = dis.readInt();
			inhaberBytes = new byte[len];
			dis.read(inhaberBytes);
			//Key-Länge
			len = dis.readInt();
			privKeyBytes = new byte[len];
			dis.read(privKeyBytes);
			
		    dis.close();
		    
			//Key generieren
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
			kf = KeyFactory.getInstance("RSA");
			privKey = kf.generatePrivate(privKeySpec);		
		   				
			
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privKey;
	}
	/**
	 * Liest einen öffentlichen Schlüssel aus einer Datei ein.
	 * 
	 * @param file
	 * @return
	 */
	@SuppressWarnings("deprecation")
	public PublicKey readPubKey(String file){
		PublicKey pubKey = null;
//		File filePub = new File(file);	
		KeyFactory kf;	
		byte[] inhaberBytes = null;
		byte[] keyPubBytes = null;
		
		try {
			DataInputStream dis = new DataInputStream(new FileInputStream(file));
			
			//Länge des InhaberNamens
			int len = dis.readInt();
			//InhaberBytes
			inhaberBytes = new byte[len];
			dis.read(inhaberBytes);
			//Länge des Keys
			len = dis.readInt();			
			//Key-Bytes
			keyPubBytes = new byte[len];
			dis.read(keyPubBytes);			
	       
			dis.close();					
			X509EncodedKeySpec ks = new X509EncodedKeySpec(keyPubBytes);
			kf = KeyFactory.getInstance("RSA");
			pubKey = kf.generatePublic(ks);
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return pubKey;
	}
	/**
	 * 
	 * Erzeugt einen geheimen Schlüssel für den AES-Algorithmus mit Key-Länge 256-Bit.
	 *
	 * @return
	 */
	public SecretKey generateSecretKeyForAES(){
		SecretKey secKey = null;
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyGen.init(256);
		secKey = keyGen.generateKey();
		return secKey;		
	}
	/**
	 * Erzeugt eine Signatur für den geheimen Schlüssel aus generateKeyForAES()
	 * mit dem privaten RSA-Schlüssel.
	 * Algorithmus: SHA512withRSA
	 * 
	 * @return
	 * @throws SignatureException 
	 */
	public Signature generateSignature(PrivateKey key) throws SignatureException{
//		privaten RSA_Schlüssel
		Signature sign = null;
		try {
			sign = Signature.getInstance("SHA512withRSA");
			sign.initSign(key);
			
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return sign;
	}
	/**
	 * Verschlüsselung des geheimen Schlüssels (aus generateKeyForAES)
	 * mit dem öffentlichen RSA-Schlüssels (Algorithmus RSA)
	 * 
	 * @return
	 */
	public byte[] encodeSecretKey(SecretKey secKey, PublicKey pubKey){
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.WRAP_MODE, pubKey); //Cipher.ECNRYPT_MODE
			byte[] wrapped = cipher.wrap(secKey);
			return wrapped;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	public void readAndEncryptData(String privKeyFile, String pubKeyFile, String originalFile, String resultFile){
		File file = new File(originalFile);
		Cipher cipher = null;
		//Einlesen der Datei
		try {
			DataInputStream dis = new DataInputStream(new FileInputStream(file));
			byte[] dataBytes = new byte[(int) file.length()];
			dis.read(dataBytes);
			dis.close();
			
			PrivateKey privKey = readPrivKey(privKeyFile);
			PublicKey pubKey = readPubKey(pubKeyFile);
			
			byte[] signatureBytes = null;
			
			cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			SecretKey secKey = generateSecretKeyForAES();
			
			String algoParam = secKey.getAlgorithm();
			
			//Erzeugen des encodierten geheimen Schlüssels
			byte[] encodedSecKey = encodeSecretKey(secKey, pubKey);
			cipher.init(Cipher.ENCRYPT_MODE, secKey);
//			byte[] encryptData = cipher.update(dataBytes);
			byte[] encryptData = cipher.doFinal(dataBytes);
			
//			cipher.doFinal(encodedSecKey);
			
			Signature signature = Signature.getInstance("SHA512withRSA");
			signature.initSign(privKey);
			signature.update(encryptData);
			signatureBytes = signature.sign();
//			writeDataToFile(encodedFile, encodedSecKey, signatureBytes, algoParam, encryptData);
		
			DataOutputStream dos = new DataOutputStream(new FileOutputStream(resultFile));
			dos.writeInt(encodedSecKey.length);
			//Verschlüsselter geheimer Schlüssel
			dos.write(encodedSecKey);
			//Länge der SIgnatur des geheimen Schlüssels
			dos.writeInt(signatureBytes.length);
			//Signatur des geheimen Schlüssels
			dos.write(signatureBytes);
			//Länge der algorithmischen Parameter des geheimen Schlüssels
			dos.writeInt(algoParam.length());
			//Algor. Parameter des geheimen Schlüssels
			dos.write(algoParam.getBytes());
			//Verschlüsselte Dateidaten
			dos.write(encryptData);
			
			dos.close();
			
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private void writeDataToFile(File resultFile, byte[] encodedSecKey,byte[] signature, String algoParam, byte[] encodedData) {
		try {
			DataOutputStream dos = new DataOutputStream(new FileOutputStream(resultFile));
			dos.writeInt(encodedSecKey.length);
			//Verschlüsselter geheimer Schlüssel
			dos.write(encodedSecKey);
			//Länge der SIgnatur des geheimen Schlüssels
			dos.writeInt(signature.length);
			//Signatur des geheimen Schlüssels
			dos.write(signature);
			//Länge der algorithmischen Parameter des geheimen Schlüssels
			dos.writeInt(algoParam.length());
			//Algor. Parameter des geheimen Schlüssels
			dos.write(algoParam.getBytes());
			//Verschlüsselte Dateidaten
			dos.write(encodedData);
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
