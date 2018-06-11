import java.security.*;

/**
 * Dieses Beispiel gibt alle installierten Kryptographie-Provider mit ihren unterstützten Algorithmen aus.
 */
public class ShowProv {
	public static void main(String[] args) {

		for (Provider provider : Security.getProviders()) {
			System.out.println("\n------------------- Provider: " + provider.getName() + " ------------------------------");
			System.out.println(provider.getInfo());
			for (String key : provider.stringPropertyNames())
				System.out.println("\t" + key + "\t" + provider.getProperty(key));
		}
	}
}
