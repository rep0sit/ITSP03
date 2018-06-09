/**
 * 
 */
package itsp03;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Nelli Welker, Etienne Onasch
 *
 */
public class RSF {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		RSF rsf = new RSF();
		rsf.readDataAndDecodeData(args[0],args[1],args[2],args[3]);
	}
	/**
	 * Liest einen privaten Schlüssel aus einer Datei ein.
	 * 
	 * @param file
	 * @return
	 */
	public PrivateKey readPrivKey(String file){
		PrivateKey privKey = null;
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
	public PublicKey readPubKey(String file){
		PublicKey pubKey = null;
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
	 * Einlesen einer .ssf-Datei, Entschluesselung des geheimen Schluessels
	 * mit dem privaten RSA-Schluessel, Entschluesselung des geheimen Schluessels
	 * AES im Counter-Mode) mit Anwendung der uebermittelten algorithmischen Parameter
	 * sowie Erzeugung einer Klartext-Ausgabedatei
	 * 
	 * @param decodedFile 
	 * @param encodedFile 
	 * @param pubKeyFile 
	 * @param privKeyFile 
	 * 
	 */
	public void readDataAndDecodeData(String privKeyFile, String pubKeyFile, String encodedFile, String decodedFile){
		try {
			DataInputStream dis = new DataInputStream(new FileInputStream(encodedFile));
			int len = dis.readInt();
			int count = len;
			//Einlesen des geheimen Schluessels
			byte[] secKeyBytes = new byte[len];
			dis.read(secKeyBytes);
			count += len;
			//Einlesen der Signatur
			len = dis.readInt();
			byte[] signatureBytes = new byte[len];
			count += len;
			dis.read(signatureBytes);
			//Einlesen der algorithm. Parameter
			len = dis.readInt();
			count += len;
			byte[] algoParamBytes = new byte[len];
			dis.read(algoParamBytes);
			
			File file = new File(encodedFile);
			byte[] encodedDataBytes = new byte[count];
			dis.read(encodedDataBytes);
						
			dis.close();
			
			PublicKey pubKey = readPubKey(pubKeyFile);
			PrivateKey privKey = readPrivKey(privKeyFile);
			
			//Erzeugung einer neuen AES-Schluesselspezifiktion aus Bytefolge
			SecretKeySpec skspec = new SecretKeySpec(secKeyBytes, "AES");
			
			AlgorithmParameters algoParams = AlgorithmParameters.getInstance("AES");
			algoParams.init(algoParamBytes);
			System.out.println("ALGOPARAM: "+new String(algoParamBytes));
			
			//Cipher Objekt zur Entschluesselung
			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, skspec, algoParams);
			
//			Entschluesselung der Daten
			byte[] decodedData = cipher.update(encodedDataBytes);
			byte[] decRest= cipher.doFinal();
			byte[] allDecData = concatenate(decodedData,decRest);
			
//			Signatur verifizieren
			Signature signature = Signature.getInstance("SHA512withRSA");
			signature.initVerify(pubKey);
			signature.update(encodedDataBytes); //nur eingelesene databytes (ohne cipher)
			boolean ok = signature.verify(signatureBytes);
			if(ok){
				System.out.println("Signatur verifiziert!");
			}else{
				System.out.println("Signatur nicht erfolgreich verifiziert");
			}
			
			//Write decoded data into file
			DataOutputStream dos = new DataOutputStream(new FileOutputStream(new File(decodedFile)));
			dos.write(allDecData);
			dos.close();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private byte[] decryptSecKey(byte[] secKeyBytes, PrivateKey privKey) {
		//Cipher Objekt zur Entschluesselung
		Cipher cipher = null;
		byte[] decryptedSecKey = null;
		try {
			cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
						//Entschluesselung der Daten
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			decryptedSecKey = cipher.doFinal(secKeyBytes);
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return decryptedSecKey;
	}
	/**
	 * Concatenate two byte arrays
	 */
	private byte[] concatenate(byte[] ba1, byte[] ba2) {
		int len1 = ba1.length;
		int len2 = ba2.length;
		byte[] result = new byte[len1 + len2];

		// Fill with first array
		System.arraycopy(ba1, 0, result, 0, len1);
		// Fill with second array
		System.arraycopy(ba2, 0, result, len1, len2);

		return result;
	}
}
