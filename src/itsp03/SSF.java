/**
 * 
 */
package itsp03;

import java.io.DataInputStream;
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
import javax.crypto.spec.SecretKeySpec;

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
//		System.out.println(ssf.generateKeyForAES());
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
	@SuppressWarnings("deprecation")
	public PrivateKey readPrivKey(String file){
		PrivateKey privKey = null;
		File filePriv = new File(file);
		KeyFactory kf;
		
		try {
			//Lesen des privaten RSA-Keys
			
			DataInputStream dis = new DataInputStream(new FileInputStream(filePriv));
			String inhaberLaenge = dis.readLine();
			String inhaberName = dis.readLine();
			String keyLaenge = dis.readLine();
			
			byte[] encodedPrivKey = new byte[(int)filePriv.length()];
			dis.read(encodedPrivKey);
		    dis.close();
		    
			//Key generieren
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encodedPrivKey);
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
		File filePub = new File(file);	
		KeyFactory kf;	
		
		try {
			DataInputStream dis = new DataInputStream(new FileInputStream(filePub));
			String inhaberLaenge = dis.readLine();
			String inhaberName = dis.readLine();
			String keyLaenge = dis.readLine();

			
			byte[] encodedPubKey = new byte[(int) filePub.length()];
			dis.read(encodedPubKey);				
	       
			dis.close();					
			X509EncodedKeySpec ks = new X509EncodedKeySpec(encodedPubKey);
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
		KeyGenerator keyGen;
		SecretKey key = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return key;		
	}
	/**
	 * Erzeugt eine Signatur für den geheimen Schlüssel aus generateKeyForAES()
	 * mit dem privaten RSA-Schlüssel.
	 * Algorithmus: SHA512withRSA
	 * 
	 * @return
	 * @throws SignatureException 
	 */
	public byte[] generateSignature(PrivateKey key) throws SignatureException{
//		privaten RSA_Schlüssel
		Signature sign = null;
		try {
			sign = Signature.getInstance("SHA512withRSA");
			sign.initSign(key);
			
			//save signature in a file
			byte[] signBytes = sign.sign();
			FileOutputStream fos = new FileOutputStream("sign");
			fos.write(signBytes);
			fos.close();
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return sign.sign();
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
	public void readAndEncryptData(String fileSender, String fileReceiver, String file, String resultFile){
		Cipher cipher;
		File encodedFile = new File(resultFile);
		//Einlesen der Datei
		try {
			File dataFile = new File(file);
			DataInputStream dis = new DataInputStream(new FileInputStream(dataFile));
			byte[] dataBytes = new byte[(int) dataFile.length()];
			dis.read(dataBytes);
			dis.close();
			
			cipher = Cipher.getInstance("AES/CTR/NoPadding");
			SecretKey secKey = generateSecretKeyForAES();
			String algoParam = secKey.getAlgorithm();
			
			//Erzeugen des encodierten geheimen Schlüssels
			byte[] encodedSecKey = encodeSecretKey(generateSecretKeyForAES(), readPubKey(fileReceiver));
			cipher.init(Cipher.ENCRYPT_MODE, secKey);
//			cipher.doFinal(encodedSecKey);
//			SecretKeySpec secKSpec =
			
			byte[] signature = generateSignature(readPrivKey(fileReceiver));
			
			writeDataToFile(encodedFile, encodedSecKey, signature, algoParam, cipher.doFinal(dataBytes));
		
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
			FileOutputStream fos = new FileOutputStream(resultFile);
			fos.write(String.valueOf(encodedSecKey.length).getBytes());
			//Verschlüsselter geheimer Schlüssel
			fos.write(encodedSecKey);
			//Länge der SIgnatur des geheimen Schlüssels
			fos.write(signature.length);
			//Signatur des geheimen Schlüssels
			fos.write(signature);
			//Länge der algorithmischen Parameter des geheimen Schlüssels
			fos.write(algoParam.length());
			//Algor. Parameter des geheimen Schlüssels
			fos.write(algoParam.getBytes());
			//Verschlüsselte Dateidaten
			fos.write(encodedData);
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
