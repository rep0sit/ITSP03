/**
 * 
 */
package itsp03;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 
 * Ein Programm f�r das Erstellen eines Schl�sselpaares mit der Schl�ssell�nge 2048 Bit.
 * 
 * @author Nelli Welker, Etienne Onasch
 *
 */
public class RSAKeyCreation {
	private int keySize = 2048;

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		RSAKeyCreation rsac = new RSAKeyCreation();
//		try {
//			rsac.writeToFile(args[0]);
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		try {
			rsac.createRSAKeys(args[0]);
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
//		System.out.println("Please enter your name:");
	}
	
	private void writeToFile(String inhaber) throws IOException
	{
		File genFile = new File(inhaber+".end");
		FileOutputStream out = new FileOutputStream(genFile);
		out.write(inhaber.getBytes());
        out.write(String.valueOf(inhaber.length()).getBytes());
        out.write("L�ngeSchl�ssel".getBytes());
        out.flush();
        out.close();
        System.out.println("done");
	}
	/**
	 * 
	 * @param inhaber
	 * @throws NoSuchAlgorithmException
	 * @throws IOException 
	 */
	private void createRSAKeys(String inhaber) throws NoSuchAlgorithmException, IOException {
		 
        File pubKeyFile = new File(inhaber+".pub");
        File privKeyFile = new File(inhaber+".prv");
        DataOutputStream dosPub = new DataOutputStream(new FileOutputStream(pubKeyFile));
        DataOutputStream dosPriv = new DataOutputStream(new FileOutputStream(privKeyFile));
        
		//Keypair erzeugen
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.genKeyPair();
       
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
		
        byte[] inhaberBytes = inhaber.getBytes();
        byte[] pubKeyBytes = pubKey.getEncoded();
        byte[] privKeyBytes = privKey.getEncoded();
        
        dosPub.writeInt(inhaberBytes.length);
        dosPub.write(inhaberBytes);
        dosPub.writeInt(pubKeyBytes.length);
        dosPub.write(pubKeyBytes);
        dosPub.flush();
        dosPub.close();
        
        dosPriv.writeInt(inhaberBytes.length);
        dosPriv.write(inhaberBytes);
        dosPriv.writeInt(privKeyBytes.length);
        dosPriv.write(privKeyBytes);
        dosPub.flush();
        dosPub.close();
        
        //PKCS#8
//        PKCS8EncodedKeySpec pkcs8Encoded = new PKCS8EncodedKeySpec(privKey.getEncoded());
//        out = new FileOutputStream(privKeyFile);
//        out.write(String.valueOf(inhaber.length()).getBytes());
//        out.write(System.getProperty("line.separator").getBytes());
//        out.write(inhaber.getBytes());
//        out.write(System.getProperty("line.separator").getBytes());
//        out.write(String.valueOf(pubKey.toString().length()).getBytes());
//        out.write(System.getProperty("line.separator").getBytes());
//        out.write(pkcs8Encoded.getEncoded());
//        out.flush();
//        out.close();
	}

}
