/**
 * 
 */
package itsp03;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

/**
 * 
 * Ein Programm für das Erstellen eines Schlüsselpaares mit der Schlüssellänge 2048 Bit.
 * 
 * @author Nelli Welker, Etienne Onasch
 *
 */
public class RSAKeyCreation {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Scanner sc  = new Scanner(System.in);
		System.out.println("Please enter your name:");
//		DataInputStream ins = new DataInputStream(System.in);
		
		String inhaber = args[0]; //sc.nextLine();

		try {
			createRSAKeys(inhaber);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}
	/**
	 * 
	 * @param inhaber
	 * @throws NoSuchAlgorithmException
	 */
	private static void createRSAKeys(String inhaber) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        //X509-Format
        byte[] publicKey = keyGen.genKeyPair().getPublic().getEncoded();
        //PKCS#8
        byte[] privateKey = keyGen.genKeyPair().getPrivate().getEncoded();
       
        File pubKeyFile = new File(inhaber+".pub");
        File privKeyFile = new File(inhaber+".prv");
        
        byte[] inhaberBytes = inhaber.getBytes();
        
        try {
        	//write public key into file
			FileOutputStream out = new FileOutputStream(pubKeyFile);
			String result = inhaber.length() +"\n"+ inhaberBytes+"\n"+publicKey.length+"\n"+publicKey;
			
			out.write(result.getBytes());
			out.flush();
			out.close();
			
			//write private Key into file
			FileOutputStream privOut = new FileOutputStream(privKeyFile);
			String privResult = inhaber.length() +"\n"+ inhaberBytes+"\n"+privateKey.length+"\n"+privateKey;
			
			privOut.write(privResult.getBytes());
			privOut.flush();
			privOut.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
